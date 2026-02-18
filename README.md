# 🐱 Can I Haz Reachability? 📡

**A professional tool to verify network reachability, TLS configurations, and firewall settings.**

> 😺 **O HAI!** I can haz reachability? I checkz if ur ports are open so u don't haz to guess. It's like ping but fancy. Kthxbye!

👉 Live demo: [https://cgnat.admon.me](https://cgnat.admon.me)

---

## 🐳 Docker Quick Start

```bash
docker run -d \
  --name can-i-haz-reachability \
  -p 8080:8080 \
  admonstrator/can-i-haz-reachability:latest
```

The API will be available at `http://localhost:8080`.

### Available Tags

| Tag | Description |
| --- | --- |
| `latest` | Latest stable build from `main` |
| `sha-<commit>` | Pinned build for a specific commit |

### Supported Architectures

| Architecture | Tag |
| --- | --- |
| `linux/amd64` | x86-64 (Intel/AMD) |
| `linux/arm64` | ARM 64-bit (Raspberry Pi 4/5, Apple Silicon, etc.) |

---

## 💖 Support the Project

- [GitHub Sponsors](https://github.com/sponsors/admonstrator)
- [Buy Me A Coffee](https://buymeacoffee.com/admon)
- [Ko-fi](https://ko-fi.com/admon)
- [PayPal](https://paypal.me/aaronviehl)

---

## 📖 About

**Can I Haz Reachability?** is a robust Go-based service that verifies if specific ports on a client's IP address are reachable from the internet. It acts as an external "mirror," attempting to connect back to the requestor to validate port forwarding, detect Carrier-Grade NAT (CGNAT), and analyze firewall configurations.

Beyond simple connectivity, it offers TLS certificate analysis and service banner grabbing, making it an essential tool for network troubleshooting and verification.

---

## ✨ Features

- 🚀 **Port Reachability Check** – Verifies TCP connectivity to specified ports on the requestor's public IP.
- 🔒 **TLS/SSL Analysis** – Performs a detailed inspection of SSL certificates on port 443 (validity, chain, cipher suites).
- 🕵️ **Banner Grabbing** – Identifies running services (e.g., SSH versions) by retrieving their initial connection banner.
- 🛡️ **Reflector Challenge** – Supports a token-based challenge system to verify ownership of the target server.
- 🛑 **Rate Limiting** – Includes built-in, IP-based rate limiting to prevent abuse.
- 🙈 **Privacy Focused** – Logs are strictly anonymized. Private/internal IP ranges are blocked by default.

---

## 🎛️ Configuration

The container is configured via environment variables.

| Variable | Description | Default |
| --- | --- | --- |
| `REFLECTOR_PORT` | The TCP port the server listens on. | `8080` |
| `REFLECTOR_TIMEOUT` | Connection timeout for reachability checks. | `5s` |
| `REFLECTOR_ALLOWED_PORTS` | Comma-separated list of ports allowed to be tested. | `80,443,8080,8443` |
| `REFLECTOR_RATE_LIMIT_PER_MIN` | Maximum number of requests per IP per minute. | `10` |
| `REFLECTOR_LOG_DIR` | Directory where application logs are stored. | `/logs` |

**Example with custom configuration:**

```bash
docker run -d \
  --name can-i-haz-reachability \
  -p 8080:8080 \
  -e REFLECTOR_ALLOWED_PORTS="22,80,443,8080" \
  -e REFLECTOR_RATE_LIMIT_PER_MIN=20 \
  -v /var/log/reflector:/logs \
  admonstrator/can-i-haz-reachability:latest
```

---

## 📚 API Usage

### Detailed Check (`GET /check`)
Performs a comprehensive scan of the requested ports.

**Query Parameters:**
- `ports`: Comma-separated list of ports to check (e.g., `80,443`).
- `tls_analyze`: Set to `true` to enable TLS certificate analysis (Port 443 only).
- `banner`: Set to `true` to attempt banner grabbing.

```bash
curl "http://localhost:8080/check?ports=80,443&tls_analyze=true"
```

### Simple Check (`GET /simple`)
Returns a concise `yes` or `no` string, ideal for automated scripts.

```bash
curl "http://localhost:8080/simple?port=443"
# Output: yes
```

### Health Check (`GET /health`)
Returns the service status and basic runtime statistics.

---

## 🔍 Privacy & Security

Access logs automatically anonymize client IP addresses (masking the last octet). The service refuses to scan private or internal IP ranges (RFC 1918) to prevent misuse as an internal network scanner.

---

## 🔗 Links

- [GitHub Repository](https://github.com/Admonstrator/can-i-haz-reachability)
- [Report Issues](https://github.com/Admonstrator/can-i-haz-reachability/issues)
- [GL.iNet Toolbox](https://github.com/Admonstrator/glinet-toolbox)

---

## 📜 License

MIT License – see [LICENSE](https://github.com/Admonstrator/can-i-haz-reachability/blob/main/LICENSE) for details.

---

**Made with ❤️ by [Admon](https://github.com/Admonstrator)**

<div align="center">

_Last updated: 2026-02-18_

</div>
