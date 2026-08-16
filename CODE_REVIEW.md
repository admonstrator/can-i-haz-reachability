# Code-Review: Can I Haz Reachability? (Reflector)

**Erstellt:** 2026-08-16 · **Methodik:** 3 unabhängige Deep-Reviews mit Claude Opus 5 (Reasoning „xHigh"), orchestriert von Claude Fable 5, mit anschließender eigener Verifikation zentraler Befunde am Kontrollfluss und teils empirisch (Go-Repro).

Reviewt wurde der gesamte relevante Quellcode: `cmd/`, `internal/**`, `web/static/**` (inkl. `script.js`, `test.sh`), Deploy-Configs (Dockerfile, docker-compose, Caddyfile, Podman-Quadlet) und die GitHub-Workflows.

---

## Gesamteindruck

Der Dienst ist für seinen Zweck erfreulich kompakt, sauber in `cmd/` + `internal/` geschnitten und kommt mit nur zwei — tatsächlich genutzten — Dependencies aus. `GetClientIP` mit der Rechts-nach-links-Auswertung vertrauenswürdiger Proxies ist überdurchschnittlich sorgfältig gemacht, die Log-Anonymisierung ist vorhanden, und es gibt eine Port-Allowlist.

In der Umsetzung brechen jedoch mehrere belegbare Sicherheits- und Korrektheitslücken die zentrale Zusicherung des Projekts — *„Wir verbinden uns nur zu der IP, die uns gefragt hat. Wir können keine beliebigen IPs scannen."* (FAQ, `index.html:105`). Die wichtigsten:

- **Read-SSRF** über `challenge_path` (empirisch verifiziert),
- die mitgelieferte **Caddy-Konfiguration macht den Dienst zum offenen Portscanner** (frei setzbarer `CF-Connecting-IP`-Header),
- ein **Divide-by-Zero-Panic** bei `REFLECTOR_RATE_LIMIT_PER_MIN=0` (empirisch verifiziert),
- `AnalyzeTLS` **ignoriert Context/Timeout** → hängende Goroutinen & Socket-Leak.

Dazu kommen ein Data Race, ein wirkungsloses Graceful-Shutdown, ein Allowlist-Bypass, verschluckte Frontend-Fehler und ein `test.sh`, das den Firewall-Vorzustand nicht zuverlässig wiederherstellt. `go vet` ist sauber, aber `gofmt -l` meldet 5 von 8 Go-Dateien als unformatiert, und es gibt **weder Tests noch ein Build-/Qualitäts-CI**.

**Befund-Übersicht:** 2 kritisch · 7 hoch · 10 mittel · 5 niedrig — plus 10 Optimierungen und 8 Feature-Ideen.

> Legende: 🔴 kritisch · 🟠 hoch · 🟡 mittel · ⚪ niedrig · ✅ = von mir verifiziert (Repro/Kontrollfluss) · [3/3] = von allen drei Reviews unabhängig gefunden.

---

## 1. Fehler + Fixes

### 🔴 Kritisch

#### 1.1 — Read-SSRF: `challenge_path` wird ungefiltert in die Ziel-URL geklebt ✅ [3/3]
**Ort:** `internal/scanner/scanner.go:130` (Eingabe aus `internal/api/handlers.go:163`)

`VerifyChallenge` baut die URL mit `fmt.Sprintf("http://%s:%d%s", host, port, path)`, wobei `path` ungeprüft aus dem Query-Parameter `challenge_path` stammt. Beginnt der Wert mit `@`, rutscht `host:port` in den **Userinfo-Teil** der URL und der Angreifer bestimmt den Ziel-Host.

Empirisch verifiziert (Go `net/url`):

```
challenge_path = "@169.254.169.254/latest/meta-data/"
→ http://203.0.113.7:80@169.254.169.254/latest/meta-data/
→ effektiver Host = 169.254.169.254   (Cloud-Metadaten!)

challenge_path = "@127.0.0.1:8080/health"
→ effektiver Host = 127.0.0.1:8080     (Reflector-Loopback)
```

Vorbedingung ist nur, dass `challenge` gesetzt ist und ein erlaubter Port (Default 80) auf der eigenen IP offen ist — für einen Angreifer trivial (ein beliebiger TCP-Listener genügt). Die ersten 256 Bytes der Antwort werden über `ChallengeRes.Received` **an den Aufrufer zurückgespiegelt** → Read-SSRF mit Datenexfiltration (Cloud-Metadaten, interne RFC1918-Dienste, Container-Netze). Der `IsPrivateIP`-Filter greift hier nicht, weil er nur auf die Client-IP angewandt wird, nicht auf das Challenge-Ziel. Zweiter, unabhängiger Pfad: `&http.Client{}` folgt bis zu 10 Redirects — ein `302` vom eigenen Port-80-Server erreicht dasselbe Ziel. Verschärfend: `Access-Control-Allow-Origin: *` (`handlers.go:74`) erlaubt jeder fremden Website, das Ergebnis im Browser eines Besuchers auszulesen.

**Fix:** Pfad strikt validieren, Redirects verbieten, Verbindung hart an die verifizierte Client-IP pinnen:

```go
if path == "" {
    path = "/.well-known/reflector/" + url.PathEscape(token)
}
if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "@?#\\") {
    return &ChallengeRes{Verified: false, Error: "invalid_challenge_path", Expected: token}
}
u := &url.URL{Scheme: "http", Host: formatHostPort(host, port), Path: path}
req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)

client := &http.Client{
    CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
    Transport: &http.Transport{
        // Ziel-Host aus URL/Headern ignorieren, IMMER zur geprüften Client-IP dialen:
        DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
            return (&net.Dialer{}).DialContext(ctx, network, formatHostPort(host, port))
        },
    },
}
```
Zusätzlich `token` gegen `^[A-Za-z0-9_-]{8,64}$` validieren und `challenge` längenbegrenzen.

#### 1.2 — Caddyfile übernimmt frei setzbaren `CF-Connecting-IP`-Header → offener Portscanner [3/3]
**Ort:** `deploy/caddy/Caddyfile:11` (identisch in :51, :73)

`header_up X-Forwarded-For {http.request.header.CF-Connecting-IP}` setzt den Vertrauens-Header aus einem Request-Header, den **jeder Client frei wählen kann**. Es gibt keine Prüfung, ob der Request wirklich von Cloudflare kommt (kein `trusted_proxies`, keine Firewall-Vorgabe im Repo). Wer den Origin direkt erreicht (Origin-IP ist per DNS-History, Certificate-Transparency-Logs oder Subdomain-Scan meist trivial zu finden), schickt `CF-Connecting-IP: <beliebig>`; Go sieht als `RemoteAddr` `127.0.0.1` (laut Default-`TrustedProxies` vertrauenswürdig) und `GetClientIP` liefert die gefälschte IP zurück.

Folgen: (a) der Dienst **scannt beliebige fremde Hosts** auf 22/80/443/8080/8443 inkl. Banner-Grabbing und TLS-Analyse — genau das, was README und FAQ ausschließen; (b) das IP-Rate-Limit ist wirkungslos (jeder gefälschte Wert bekommt einen eigenen Bucket); (c) zusammen mit 1.1 wird daraus SSRF gegen beliebige Ziele. Umgekehrt macht dieselbe Zeile den Dienst **ohne** Cloudflare komplett unbenutzbar: `CF-Connecting-IP` ist dann leer, XFF wird leer gesetzt, `GetClientIP` fällt auf `127.0.0.1` zurück → jeder Request endet in `403 private_ip`.

**Fix:** Cloudflare-Header nur akzeptieren, wenn der Peer wirklich Cloudflare ist, und Caddy die Ableitung machen lassen:

```caddyfile
{
    servers {
        trusted_proxies static 173.245.48.0/20 103.21.244.0/22 … 2c0f:f248::/32
        client_ip_headers CF-Connecting-IP
    }
}
reflector.example.com {
    @api path /simple /health /check
    handle @api {
        reverse_proxy localhost:8080 {
            header_up -CF-Connecting-IP
            header_up X-Real-IP {http.request.client_ip}
            header_up X-Forwarded-For {http.request.client_ip}
        }
    }
}
```
Zusätzlich im README dokumentieren, dass der Origin per Firewall/`cloudflared` auf die Cloudflare-Ranges beschränkt werden **muss**.

---

### 🟠 Hoch

#### 1.3 — `AnalyzeTLS` ignoriert Context & Timeout → hängende Goroutinen, FD-Leak [3/3]
**Ort:** `internal/scanner/scanner.go:85`

`tls.DialWithDialer(dialer, …)` wird mit einem leeren `&net.Dialer{}` (ohne `Timeout`/`Deadline`) aufgerufen. `DialWithDialer` leitet genau diese Werte an TCP-Connect **und** TLS-Handshake weiter — sind sie null, gibt es keine Zeitgrenze. Der `ctx` wird erst *nach* dem Handshake (`conn.SetDeadline`, Zeile 94–96) verwendet und wirkt damit nie auf den Handshake. Ein Host, der auf 443 TCP annimmt und dann schweigt (Tarpit), lässt den Aufruf praktisch unbegrenzt blockieren; die Goroutine hängt an `wg.Wait()`, der Request läuft über sein `Timeout+2s`-Budget hinaus, Socket und Goroutine bleiben bis zum OS-TCP-Timeout (Minuten) bestehen. Da `parsePorts` Duplikate zulässt (`?ports=443,443,443,443,443`), erzeugt ein einziger Request mehrere hängende Verbindungen.

**Fix:** Kontext-gebundenen TLS-Dialer verwenden:

```go
d := tls.Dialer{
    NetDialer: &net.Dialer{},
    Config:    &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
}
conn, err := d.DialContext(ctx, "tcp", formatHostPort(host, port))
```
(`MinVersion: TLS 1.0` behebt zugleich Befund 1.7.) Idealerweise die TCP-Verbindung aus `CheckPort` wiederverwenden statt neu aufzubauen (siehe Optimierung O1).

#### 1.4 — `REFLECTOR_RATE_LIMIT_PER_MIN=0` → Integer-Divide-by-Zero-Panic ✅ [3/3]
**Ort:** `internal/limiter/limiter.go:35`

`rate.NewLimiter(rate.Every(time.Minute/time.Duration(i.rateLimit)), i.rateLimit)` — bei `rateLimit == 0` ergibt `time.Minute / 0` einen **`runtime error: integer divide by zero`** (empirisch bestätigt). Der Panic passiert im ersten Request-Handler (`GetLimiter`); `net/http` recovered die Goroutine, aber der Client bekommt eine abgebrochene Verbindung, und es landet nichts im `error.log`. Negative Werte (z. B. `-1`) sind noch tückischer: `rate.Every(negativ)` liefert eine negative Rate, die den Limiter faktisch **deaktiviert** — Rate-Limiting still ausgeschaltet.

**Fix:** In `LoadConfig` validieren und klemmen:

```go
if cfg.RateLimitPerMin < 1 {
    log.Printf("invalid rate limit %d, falling back to 10", cfg.RateLimitPerMin)
    cfg.RateLimitPerMin = 10
}
```

#### 1.5 — `parsePorts` umgeht die Allowlist bei leerem `ports`-Parameter [2/3]
**Ort:** `internal/api/handlers.go:44`

Bei leerem Parameter gibt `parsePorts` **`[]int{80, 443}` zurück, ohne gegen `AllowedPorts` zu prüfen**. Setzt ein Betreiber `REFLECTOR_ALLOWED_PORTS` ohne 80/443 (etwa nur `8443`), scannt ein Request ohne `ports=` trotzdem 80 und 443. Die Allowlist ist damit im Default-Pfad wirkungslos.

**Fix:** Auch den Default gegen die Allowlist filtern:

```go
if portsParam == "" {
    var def []int
    for _, p := range []int{80, 443} {
        if h.cfg.AllowedPorts[p] { def = append(def, p) }
    }
    return def, nil
}
```

#### 1.6 — Frontend verschluckt alle API-Fehler im Standard-Pfad [2/3]
**Ort:** `web/static/script.js:167` / `:188` (Parallel-Pfad `Promise.allSettled`)

Im kombinierten IPv4/IPv6-Pfad wird die Response direkt mit `await response.json()` verarbeitet, **ohne `response.ok` zu prüfen**. Eine `429`- (Rate-Limit) oder `403`-Antwort ist valides JSON mit `success:false` — `splitResultsByIPVersion` findet aber `results`-Objekte und rendert daraus ein **leeres, scheinbar erfolgreiches Ergebnis**, statt die Fehlermeldung anzuzeigen. Der Nutzer sieht „keine Ports erreichbar" statt „Rate-Limit überschritten". (Der Einzel-IP-Pfad prüft `response.ok` korrekt — inkonsistent.)

**Fix:** In beiden `allSettled`-Zweigen nach `response.json()` prüfen und bei `!response.ok || data.success === false` einen Fehler werfen, damit `showError` greift.

#### 1.7 — Schwache TLS-Versionen (1.0/1.1) sind nie erkennbar [1/3]
**Ort:** `internal/scanner/scanner.go:87` + `:228`

Der TLS-Config setzt kein `MinVersion`. Seit Go 1.22 ist der Default-Mindestwert **TLS 1.2**. Ein Server, der nur TLS 1.0/1.1 anbietet, führt daher zu einem **Handshake-Fehler** → `AnalyzeTLS` gibt `err` zurück, `result.TLS` bleibt `nil`. Damit sind die `weak_tls_version`-Warnung in `generateTLSWarnings` und die `"TLS 1.0"/"TLS 1.1"`-Fälle in `tlsVersionName` **toter, unerreichbarer Code** — das im README beworbene Erkennen schwacher Ciphers/Versionen funktioniert für genau die schwachen Versionen nicht.

**Fix:** `MinVersion: tls.VersionTLS10` im TLS-Config setzen (siehe 1.3), damit veraltete Server überhaupt gehandshaked und als „weak" gemeldet werden können.

#### 1.8 — `test.sh` stellt den Firewall-Vorzustand nicht zuverlässig wieder her [3/3]
**Ort:** `web/static/test.sh:569` (`cleanup`) / Zustandslogik ab `:650`

`cleanup` prüft nur das aggregierte `FIREWALL_WAS_OPEN` (1 wenn IPv4 **oder** IPv6 vorher offen war). War z. B. nur IPv4 offen, IPv6 aber nicht, bleibt `FIREWALL_WAS_OPEN=1` → die Funktion lässt **beide** Regeln bestehen, obwohl die IPv6-Regel neu vom Skript angelegt wurde. Umgekehrt kann `close_firewall` eine **bereits vorher vorhandene** Regel löschen, weil nicht zwischen „vom Skript angelegt" und „vom Nutzer angelegt" unterschieden wird. Wenn eine Regel vorher existierte, wird zudem nur `enabled` und `dest_port` überschrieben — der ursprüngliche `dest_port` geht verloren und wird beim Aufräumen nicht restauriert. Ergebnis: entweder bleiben Test-Ports offen oder Nutzerregeln werden verändert/gelöscht — sicherheitsrelevant für ein Skript, das als root Firewall-Regeln anfasst.

**Fix:** Vorzustand pro Familie **und** pro Regel getrennt merken (existierte die Regel? war sie enabled? welcher `dest_port`?) und im `cleanup` exakt diesen Zustand wiederherstellen — nur selbst angelegte Regeln löschen, fremde unangetastet lassen bzw. auf den gemerkten `dest_port`/`enabled`-Wert zurücksetzen.

#### 1.9 — DOM-XSS: Zertifikats- und Banner-Daten unescaped in `innerHTML` [3/3]
**Ort:** `web/static/script.js:303` (Subject/Issuer/DNS-Names), `:357` (Banner), `:474`

`displayResults` interpoliert `cert.subject`, `cert.issuer`, `cert.dns_names`, `result.banner` u. a. direkt in `item.innerHTML`. Diese Werte stammen aus dem TLS-Zertifikat bzw. Service-Banner des **gescannten Ziels**. Im Normalfall ist das die eigene IP des Nutzers (Self-XSS, harmlos) — **aber** unter CGNAT teilen sich mehrere Kunden dieselbe öffentliche IPv4: Ein Angreifer im selben CGNAT-Pool kann Zertifikat/Banner mit einem Payload präparieren, den ein anderer Nutzer mit derselben öffentlichen IP dann in seinem Browser gerendert bekommt. In Kombination mit 1.2 (erzwungenes Scannen beliebiger IPs) wird der Vektor breiter.

**Fix:** Werte per `textContent` setzen bzw. vor der Interpolation escapen. Am saubersten: die betroffenen Felder über `document.createElement` + `el.textContent = value` statt Template-Literale + `innerHTML` rendern. Zusätzlich eine `Content-Security-Policy` (siehe 1.24) als Defense-in-Depth.

---

### 🟡 Mittel

#### 1.10 — Data Race auf `checksCount` [3/3]
**Ort:** `internal/api/handlers.go:181` (Write) / `:253` (Read)

`h.checksCount++` läuft in `HandleCheck` nebenläufig (ein Request pro Goroutine), wird aber ohne Synchronisation inkrementiert und in `HandleHealth` gelesen — ein Data Race (mit `-race` nachweisbar), der zu verlorenen Zählungen und undefiniertem Verhalten führt.
**Fix:** `atomic.Int64` verwenden: `h.checksCount.Add(1)` bzw. `h.checksCount.Load()`.

#### 1.11 — Graceful Shutdown ist wirkungslos [3/3]
**Ort:** `cmd/reflector/main.go:56–64`

Beim Signal ruft eine Goroutine `server.Shutdown(ctx)`. Sobald `Shutdown` die Listener schließt, kehrt `ListenAndServe` im Main mit `ErrServerClosed` zurück, `main` läuft weiter, `defer appLogger.Close()` greift und der Prozess endet — **bevor** `Shutdown` die laufenden Requests gedrained hat. Der „graceful" Teil verpufft.
**Fix:** Über einen Kanal auf den Abschluss von `Shutdown` warten, bevor `main` zurückkehrt (`idleClosed := make(chan struct{})`; in der Shutdown-Goroutine nach `Shutdown` `close(idleClosed)`; nach `ListenAndServe` `<-idleClosed`).

#### 1.12 — `/simple`: ungültiger `port`-Parameter fällt still auf 80 zurück [3/3]
**Ort:** `internal/api/handlers.go:222–227`

Schlägt `strconv.Atoi(pStr)` fehl, bleibt `port` auf dem Default 80 — `?port=abc` liefert also klammheimlich das Ergebnis für Port 80 statt einer Fehlermeldung. (Ein Wert außerhalb der Allowlist wird dagegen mit 400 abgelehnt — inkonsistent.)
**Fix:** Bei `err != nil` mit `400` antworten statt still auf 80 zu fallen.

#### 1.13 — `parsePorts` dedupliziert nicht → Request-Amplification [2/3]
**Ort:** `internal/api/handlers.go:48–65`

`?ports=443,443,443,443,443` erzeugt fünf identische Scans (in `ScanAllConcurrent` fünf Goroutinen), die im Ergebnis-Map auf denselben Key kollabieren — die Arbeit wird also verrichtet, das Resultat verworfen. In Verbindung mit 1.3 (hängende TLS-Handshakes) ein wirksamer DoS-Amplifier. Zudem wird das „max 5"-Limit erst **nach** der Schleife geprüft.
**Fix:** Vor dem Scan deduplizieren (`map[int]struct{}`) und das Anzahl-Limit vor dem Parsen/Scannen prüfen.

#### 1.14 — `IsPrivateIP` deckt CGNAT (100.64.0.0/10) und weitere reservierte Bereiche nicht ab [3/3]
**Ort:** `internal/util/ip.go:12`

Die Blockliste enthält RFC1918, Loopback, Link-Local und IPv6-Pendants, aber **nicht** `100.64.0.0/10` (RFC6598, CGNAT) — ausgerechnet den Bereich, um den sich die Anwendung dreht — sowie nicht `0.0.0.0/8`, `192.0.0.0/24`, `240.0.0.0/4`, Multicast `224.0.0.0/4`. Reicht ein Proxy die CGNAT-Adresse im XFF weiter, versucht der Reflector eine Verbindung ins Trägernetz des Providers. `net.ParseCIDR`-Fehler werden zudem ignoriert (`_`).
**Fix:** Bereiche ergänzen; CGNAT separat behandeln und als eigenes Diagnosesignal ausgeben (siehe Feature F2) statt es nur zu blocken. Ab Go 1.18 allokationsfrei mit `net/netip`.

#### 1.15 — `test.sh`: gierige `grep`/`sed`-Regexe ordnen TLS-Daten dem falschen Port zu [2/3]
**Ort:** `web/static/test.sh:190` u. a. (`get_tls_version`, `get_cert_subject`, …)

Muster wie `sed -n "s/.*\"$port\":{.*\"version\":\"\([^\"]*\)\".*/.../p"` matchen über Objektgrenzen hinweg (`.*` ist greedy). Bei mehreren Ports in einer Antwort kann so die TLS-Version/das Zertifikat eines **anderen** Ports angezeigt werden. `parse_json_result` mit `\"$port\":{[^}]*}` bricht zudem bei verschachtelten Objekten (das Port-Objekt enthält `{…}` für `tls`/`certificate`).
**Fix:** Das Port-Objekt einmal robust extrahieren (bevorzugt `jq`, falls auf dem Zielsystem verfügbar; sonst ein an `}` verankertes, nicht-gieriges Muster) und alle Felder aus diesem Ausschnitt lesen.

#### 1.16 — `test.sh`: `--ports`/`--timeout` ohne Argument → Endlosschleife [1/3]
**Ort:** `web/static/test.sh:596–608`

`--ports) PORTS="$2"; shift 2;;` — steht `--ports` am Ende ohne Wert, ist `$2` leer und `shift 2` scheitert (nur 1 Argument vorhanden). In `dash`/`ash` bleibt `$#` dann unverändert → die `while [ $# -gt 0 ]`-Schleife terminiert nicht.
**Fix:** Argumentpräsenz prüfen (`[ -n "${2:-}" ] || { log ERROR "--ports needs a value"; exit 1; }`) und `set -u` aktivieren.

#### 1.17 — Escape-Taste scrollt die Seite immer nach oben [2/3]
**Ort:** `web/static/script.js:1389` (Handler) → `closeWizard` `:1132`

Der globale `keydown`-Handler ruft bei `Escape` **immer** `closeWizard()`, auch wenn kein Modal offen ist. `closeWizard` setzt `body.style.top = ''` und `window.scrollTo(0, parseInt(scrollY||'0')*-1)` — bei nicht gesetztem `top` also `scrollTo(0, 0)`. Folge: Escape irgendwo auf der Seite springt nach ganz oben.
**Fix:** In `closeWizard`/`closeRouterTestModal` früh zurückkehren, wenn das jeweilige Modal nicht sichtbar ist.

#### 1.18 — `docker-compose.yml` veröffentlicht die API auf allen Interfaces [2/3]
**Ort:** `docker-compose.yml:8`

`"8080:8080"` bindet auf `0.0.0.0` → der Reflector ist unter der Host-IP direkt erreichbar, **am Reverse Proxy vorbei** (ohne TLS, ohne die Cloudflare-Header-Logik). Das Podman-Quadlet macht es mit `PublishPort=127.0.0.1:8080:8080` richtig. Zudem fehlen dem Compose-Setup die Härtungen des Quadlets (`DropCapability=ALL`, `PidsLimit`).
**Fix:** `"127.0.0.1:8080:8080"` und Härtung angleichen (`cap_drop: [ALL]`, `read_only: true`, `security_opt: ["no-new-privileges:true"]`, `pids_limit`, `mem_limit`).

#### 1.19 — Rate-Limit pro voller IPv6-Adresse wirkungslos; Limiter-Map wächst unbegrenzt [1/3]
**Ort:** `internal/limiter/limiter.go:32` (+ `internal/util/ip.go`)

Der Limiter-Key ist die volle Client-IP als String. Bei IPv6 hat ein Nutzer typischerweise ein ganzes `/64` (oder größer) — der Angreifer rotiert einfach die Adresse und **umgeht das Limit pro Request**, während jede neue Adresse einen Map-Eintrag anlegt (Cleanup erst nach 5–10 min → unbeschränktes Wachstum unter Last).
**Fix:** Für IPv6 auf `/64` normalisieren (Prefix als Key), für IPv4 auf die volle Adresse; zusätzlich eine harte Obergrenze für die Map (siehe O2).

---

### ⚪ Niedrig

#### 1.20 — Doppelte DOM-ID `details-<port>`: SSH-Details nie aufklappbar [2/3]
**Ort:** `web/static/script.js:291` (TLS) & `:394` (SSH)

Hat ein Port sowohl TLS- als auch Banner-Daten, erzeugen beide Blöcke ein Element mit `id="details-<port>"`. `getElementById` trifft immer das erste — der SSH-Block lässt sich nicht aufklappen.
**Fix:** Eindeutige IDs (`details-tls-<port>` / `details-ssh-<port>`).

#### 1.21 — `AnonymizeIP` mutiert das Backing-Array der übergebenen IP [2/3]
**Ort:** `internal/util/ip.go:76`

Im IPv6-Zweig wird `ip.To16()` in-place genullt. `To16()` gibt bei 16-Byte-Slices dieselbe Referenz zurück — würde `AnonymizeIP` je auf einer geteilten `net.IP` aufgerufen, verändert es den Aufrufer-Slice. Aktuell nur auf frisch geparsten IPs benutzt (kein akuter Bug), aber eine latente Aliasing-Falle.
**Fix:** Auf einer Kopie arbeiten (`b := make(net.IP, len(ip16)); copy(b, ip16)`).

#### 1.22 — `gofmt` meldet 5/8 Dateien; kein CI, keine Tests ✅ [3/3]
**Ort:** `handlers.go`, `config.go`, `limiter.go`, `scanner.go`, `ip.go` (verifiziert per `gofmt -l .`)

`go vet ./...` ist sauber, aber fünf Dateien sind nicht gofmt-konform, und es existiert **kein** `*_test.go` und kein Workflow, der Go baut/testet/lintet (nur Pages-Deploy und Badge-Update).
**Fix:** `gofmt -w .` und ein CI-Job (`go vet`, `gofmt -l` als Gate, `go build`, `go test ./...`), plus erste Unit-Tests für `GetClientIP`, `parsePorts`, `AnonymizeIP`, `VerifyChallenge`.

#### 1.23 — Badge-Workflow liest die Version aus der falschen Datei [3/3]
**Ort:** `.github/workflows/update-badges.yml:37`

`grep 'Version:        "' cmd/reflector/main.go` — `main.go` enthält aber **kein** `Version`-Feld (das steht in `internal/api/handlers.go:252`, `SCRIPT_VERSION` in `test.sh:6`). `script_version` ist also leer, und der Platzhalter `{{SCRIPT_VERSION}}` im README wird durch einen Leerstring ersetzt.
**Fix:** Auf die tatsächliche Quelle zeigen (z. B. `grep 'SCRIPT_VERSION=' web/static/test.sh`) oder die Version zentral per `ldflags`/Konstante setzen.

#### 1.24 — Statik ohne Security-Header, CWD-abhängiger Pfad, Doppelauslieferung [2/3]
**Ort:** `cmd/reflector/main.go:43`

`http.FileServer(http.Dir("./static"))` funktioniert nur, wenn das Arbeitsverzeichnis `/app` ist — lokales `go run ./cmd/reflector` liefert 404 für alle Frontend-Pfade. Gleichzeitig liefert die Caddy-Config dieselben Dateien aus `/var/www/reflector/static` (zwei Quellen der Wahrheit). Es werden keine Security-Header gesetzt (CSP, `X-Content-Type-Options`, `Referrer-Policy`).
**Fix:** Assets per `//go:embed` in die Binary aufnehmen (löst CWD-Abhängigkeit und Doppelauslieferung) und Security-Header inkl. CSP setzen. Als Nebeneffekt entfällt `COPY web/static ./static` im Dockerfile.

*(Weitere Kleinbefunde, die mind. ein Review nannte: `go.mod` — Modulpfad `github.com/glinet/reflector` passt nicht zum Repo `admonstrator/can-i-haz-reachability` und enthält einen `// filepath:`-Editor-Artefakt-Kommentar; `logger.LogError` ist toter Code, `error.log` bleibt immer leer; `HealthResponse` liefert irreführende/erfundene Werte — siehe 2. & 3.)*

---

## 2. Optimierungen

**O1 — Eine TCP-Verbindung pro Port statt bis zu drei.** `internal/scanner/scanner.go`
Standardfall `ports=80,443&tls_analyze=true` (was das Frontend immer schickt) öffnet pro Port zwei bis drei Verbindungen: `CheckPort` (Latenzmessung), dann `AnalyzeTLS` bzw. `GrabBanner` neu. Jede zusätzliche Verbindung kostet einen vollen RTT gegen eine oft schmale Consumer-Leitung und verdoppelt die Last auf dem — häufig leistungsschwachen — Router des Nutzers. **Fix:** Verbindung aus `CheckPort` zurückgeben und für TLS (`tls.Client(conn, …).HandshakeContext`) bzw. Banner (`conn.Read`) weiterverwenden. TLS und Banner schließen sich (443 vs. 22/21/25) ohnehin aus.

**O2 — Rate-Limiter: `RLock` im Lesepfad, Cleanup entkoppeln, Map begrenzen.** `internal/limiter/limiter.go`
Der `sync.RWMutex` wird nie als `RLock` genutzt — jeder Request nimmt den exklusiven Write-Lock, und `Cleanup` hält ihn über die **gesamte** Map. Unter einem Traffic-Peak mit vielen IPs bedeutet das lange Blockaden aller Requests und unbeschränktes Map-Wachstum. **Fix:** Lesepfad mit `RLock` + Double-Check, `lastSeen` als `atomic.Int64`, Cleanup geshardet/in Batches, plus harte Obergrenze (z. B. 100k Einträge).

**O3 — Access-Logging aus dem Request-Pfad nehmen.** `internal/logger/logger.go:71`
`LogAccess` hält einen prozessweiten Mutex und erzeugt darin pro Request einen neuen `json.Encoder`, serialisiert per Reflection und schreibt synchron auf die Datei — inklusive lumberjack-Rotation samt gzip. Während einer Rotation blockieren **alle** Requests. **Fix:** Einträge über einen gepufferten Channel an eine Drain-Goroutine mit persistentem Encoder geben (`select { case ch<-e: default: /*drop*/ }`), `Close()` wartet auf den Drain. Spart zugleich die `resultsBool`-Map pro Request (`handlers.go:176`).

**O4 — `http.Server` härten.** `cmd/reflector/main.go:45`
Es fehlen `ReadHeaderTimeout` (Slowloris-Schutz), `MaxHeaderBytes` (Default 1 MB, obwohl nur kleine Header nötig — relevant, weil XFF zerlegt wird), eine Panic-Recovery-Middleware und ein gesetzter `ErrorLog`. **Fix:** `ReadHeaderTimeout: 5s`, `ReadTimeout: 10s`, `MaxHeaderBytes: 16<<10`, schlanke `recover`-Middleware, die über `appLogger.LogError` schreibt und `500` liefert.

**O5 — `script.js` (73 KB) halbieren.** `web/static/script.js:635`
`wizardSteps` enthält für 5 Schritte je zwei vollständige HTML-Blöcke (normal + LOLcat) als Template-Literale (~30 KB); `routerTestContent` wiederholt Inhalte, die schon im HTML stehen. Jeder Besucher lädt/parst das, obwohl nur ein Bruchteil den Wizard öffnet. **Fix:** Wizard-Schritte als `<template>` ins HTML, im JS nur klonen; LOLcat-Varianten über `data-lolcat`-Attribute statt duplizierter Blöcke. Realistisch < 25 KB.

**O6 — Dockerfile: kleineres, reproduzierbares Image.** `Dockerfile`
Statisch gebaute Binary, aber `alpine:latest`-Runtime (bewegliches Ziel) plus `ca-certificates`, die der Scanner (Klartext-HTTP bzw. `InsecureSkipVerify`) gar nicht braucht; kein Build-Cache, kein `-trimpath`, drei separate `RUN`-Layer. **Fix:** `distroless/static` (oder `scratch`) als Runtime, `--mount=type=cache` für Modul-/Build-Cache, `-trimpath -ldflags "-X main.version=…"`, Statics per `go:embed` (dann kein `COPY static`), Healthcheck über ein Binary-Flag statt `wget`. Zusätzlich ein `.dockerignore` (aktuell landet u. a. `.git` im Build-Kontext).

**O7 — Caddy: `zstd` + Cache-Header, Snippets.** `deploy/caddy/Caddyfile:26`
Nur `gzip`, keinerlei `Cache-Control` — obwohl Assets über `?cachebust=1.5.1` versioniert sind. **Fix:** `encode zstd gzip`, `Cache-Control: public, max-age=31536000, immutable` für `/fonts/*`, `/app.webp`, `/favicon.ico` und `no-cache` für `index.html`. Die drei fast identischen Site-Blöcke per `import`-Snippet zusammenfassen (83 → ~40 Zeilen), damit auch die `health_*`-Direktiven konsistent sind.

**O8 — `test.sh`: Anzeige entdoppeln, Subprozesse reduzieren.** `web/static/test.sh:460`
Die IPv6-Ausgabeschleife ist eine Zeichen-für-Zeichen-Kopie der IPv4-Schleife (~120 Zeilen doppelt — Nährboden für 1.15). Jeder Extraktor startet eine eigene `echo|grep|sed`-Pipeline → ~15–20 Prozessstarts pro Port, spürbar auf MIPS/busybox-Routern. **Fix:** Eine `print_results()`-Funktion je Familie; Port-Objekt einmal in eine Variable extrahieren und alle Felder daraus lesen.

**O9 — Frontend-Ladepfad.** `web/static/index.html:23`, `script.js`
Inter-Font wird erst nach dem CSS-Parse entdeckt (`preload` fehlt); bis zu 8 externe `img.shields.io`-Badges ohne `loading="lazy"`/`width`/`height` (Layout-Shift, Drittanbieter-Requests); `console.log`/`console.error` in `toggleDetails` im Produktionscode; Ergebnisse werden einzeln per `appendChild` gehängt. **Fix:** `<link rel="preload" as="font" … crossorigin>`, Badges lokal hosten oder `loading="lazy"` + Maße, Debug-Logs entfernen, `DocumentFragment` für die Ergebnisliste.

**O10 — Kleinallokationen im Scan-Pfad.** `internal/scanner/scanner.go:336`, `:60`, `:294`
`fmt.Sprintf("%d", p)` für Map-Keys (Reflection) → `strconv.Itoa(p)`; `formatHostPort` von Hand → `net.JoinHostPort`; Ergebnis-`map`+`Mutex` bei ≤ 5 bekannten Ports → vorab dimensioniertes Slice mit festem Index (keine Synchronisation nötig). ~15 Zeilen weniger bei gleichem Verhalten.

---

## 3. Neue Features

**F1 — UDP-Erreichbarkeitstest (WireGuard/OpenVPN).** *(Aufwand: mittel)*
Der Dienst prüft nur TCP; die Zielgruppe (Selfhosting hinter CGNAT) will fast immer WireGuard auf UDP/51820 oder OpenVPN auf UDP/1194. Als Challenge-Variante sauber baubar: Client öffnet lokal einen Listener (kann `test.sh` per `nc`/`socat`), holt ein Token, der Reflector sendet ein UDP-Paket mit Token an den Client-Port und wertet die Echo-Antwort aus — ehrlicher als Raten und strukturell nah an der vorhandenen Token-Challenge.

**F2 — Explizite CGNAT-/NAT-Typ-Klassifikation statt nur Portstatus.** *(mittel)*
Der Name verspricht CGNAT-Erkennung, geliefert wird nur „Port erreichbar ja/nein". Aus vorhandenen Daten ableitbar: liegt die Client-IP in `100.64.0.0/10`? Weicht die vom Router gemeldete WAN-IP von der vom Reflector gesehenen ab (kann `test.sh` beisteuern)? Unterschied IPv4 vs. IPv6? Ergebnis: eine verständliche Diagnose („Du hast öffentliches IPv6, aber IPv4 läuft über CGNAT — nutze IPv6 oder fordere eine öffentliche IPv4 an") statt zweier roter Kreuze.

**F3 — Prometheus-/OpenMetrics-Endpoint statt Attrappen-`/health`.** *(klein)*
`/health` liefert aktuell einen nie zurückgesetzten Zähler, ein hartkodiertes `Goroutines: 0` und eine hartkodierte Version. Ein `/metrics` (Checks pro Port/Ergebnis, Rate-Limit-Treffer, Scan-Dauer-Histogramm, Anzahl Limiter-Einträge, Go-Runtime-Metriken) macht den Betrieb beobachtbar und würde die hier gefundenen Ressourcenlecks sofort sichtbar machen. Mit `expvar` sogar ohne neue Dependency; Absicherung über einen separaten Loopback-Listener.

**F4 — Teilbarer, signierter Ergebnis-Permalink.** *(klein)*
Typische Nutzung endet mit „ich poste einen Screenshot ins GL.iNet-Forum". Ein „Ergebnis teilen"-Button könnte den Report (Zeitstempel, anonymisierte IP, IP-Version, Portstatus, TLS-Zusammenfassung) als kompakten, per HMAC signierten Blob im URL-Fragment kodieren (kein Server-State, kein DB) — plus Markdown-Block zum Kopieren, den Helfer im Forum als unverfälscht erkennen können.

**F5 — Laufzeit-Konfiguration für Self-Hoster (`/config.json`).** *(klein)*
Die Hosts des Autors sind an ~6 Stellen in `script.js`, `test.sh` und `index.html` verdrahtet — jeder Fork belastet die Instanz des Autors. Ein vom Backend geliefertes `/config.json` (`ipv4_host`, `ipv6_host`, `allowed_ports`, `rate_limit`, `version`) macht das Frontend generisch: die Port-Checkboxen könnten aus `allowed_ports` generiert werden (heute hartkodiert und driften bei geänderter `REFLECTOR_ALLOWED_PORTS` auseinander), `test.sh` seine Zielliste ebenfalls daraus ziehen.

**F6 — Challenge-Feature durchgängig nutzbar machen + Freischaltung des vollen Portbereichs.** *(mittel)*
Die Reflector-Challenge existiert im Backend, wird aber von Frontend und `test.sh` nirgends genutzt und ist undokumentiert. Sinnvoll ausgebaut (Frontend-Flow + `test.sh`-Integration + Doku) könnte ein erfolgreich verifizierter Ownership-Nachweis den Scan **des vollen Portbereichs** für die eigene, nachgewiesene IP freischalten — nützlich für Nutzer, die andere Ports testen wollen, ohne die Allowlist global aufzuweichen.

**F7 — Erreichbarkeits-Monitoring mit Benachrichtigung.** *(groß)*
Ein einmaliger Check beantwortet „geht es jetzt?". Schmerzhafter ist „seit wann nicht mehr?" (stille CGNAT-Umstellung, gekippter DS-Lite-Tunnel). Ein optionaler Wächter-Modus: Router registriert sich per Token, der Reflector prüft im Intervall und benachrichtigt bei Statuswechsel (Webhook/ntfy/E-Mail). Erfordert allerdings echten Server-State, Scheduler, Missbrauchsschutz und Abmeldeweg — deutlich mehr als die heutige zustandslose Architektur.

**F8 — Vertiefte TLS-/HTTP-Analyse mit Bewertung.** *(mittel)*
Auf der vorhandenen TLS-Analyse aufbauend ein kompaktes Rating (Protokoll-Versionen, Cipher-Stärke, Kettengültigkeit, HSTS/Redirect-Verhalten, SAN-Abdeckung) im Stil eines vereinfachten SSL-Labs-Grades — passt zur Diagnose-Natur des Tools und macht den 443-Report deutlich wertvoller.

---

*Erstellt von Claude Fable 5 (Orchestrierung) auf Basis von drei unabhängigen Claude-Opus-5-Reviews (Reasoning „xHigh"). Kritische Befunde wurden am Kontrollfluss und, wo möglich, empirisch verifiziert.*
