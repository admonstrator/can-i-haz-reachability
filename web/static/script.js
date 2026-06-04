/**
 * ============================================================================
 * Can I Haz Reachability? - Client-Side Application
 * ============================================================================
 * 
 * @description  Web interface for checking internet reachability and port 
 *               accessibility. Tests IPv4 and IPv6 connectivity, analyzes 
 *               TLS certificates, and provides detailed connection diagnostics.
 * 
 * @author       Admon
 * @repository   admonstrator/can-i-haz-reachability
 * @license      See LICENSE file in repository root
 * 
 * Features:
 * - Parallel IPv4 and IPv6 connectivity checks
 * - TLS/SSL certificate analysis
 * - SSH banner detection
 * - LOLcat mode for fun 🐱
 * - Step-by-step wizard for troubleshooting
 * 
 * ============================================================================
 */

function inferIPVersion(clientIP) {
    if (!clientIP || typeof clientIP !== 'string') {
        return null;
    }

    if (clientIP.includes(':')) {
        return 6;
    }

    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(clientIP)) {
        return 4;
    }

    return null;
}

function getResponseIPVersion(data) {
    if (!data || typeof data !== 'object') {
        return null;
    }

    if (data.ip_version === 4 || data.ip_version === 6) {
        return data.ip_version;
    }

    return inferIPVersion(data.client_ip);
}

function splitResultsByIPVersion(...responses) {
    const grouped = {
        ipv4Data: null,
        ipv6Data: null
    };

    responses.filter(Boolean).forEach(data => {
        const ipVersion = getResponseIPVersion(data);

        if (ipVersion === 4 && !grouped.ipv4Data) {
            grouped.ipv4Data = data;
            return;
        }

        if (ipVersion === 6 && !grouped.ipv6Data) {
            grouped.ipv6Data = data;
        }
    });

    return grouped;
}

async function runCheck(ipVersion = null) {
    // Bestimme welcher Button gedrückt wurde
    let btn, btnText, loader;
    if (ipVersion === 'ipv4') {
        btn = document.getElementById('checkIPv4Btn');
    } else if (ipVersion === 'ipv6') {
        btn = document.getElementById('checkIPv6Btn');
    } else {
        btn = document.getElementById('checkBtn');
    }
    btnText = btn.querySelector('.btn-text');
    loader = btn.querySelector('.loader');
    
    const resultsArea = document.getElementById('resultsArea');
    const ipDisplay = document.getElementById('ipDisplay');
    const errorBox = document.getElementById('errorBox');
    
    // Get selected ports
    const checkboxes = document.querySelectorAll('input[type="checkbox"]:checked');
    if (checkboxes.length === 0) {
        showError(lolcatify("Please select at least one port to check."));
        return;
    }
    const ports = Array.from(checkboxes).map(cb => cb.value).join(',');

    // Reset UI
    btn.disabled = true;
    btnText.textContent = lolcatMode ? 'Wait 4 answer. Plz wait. 😺' : 'Waiting for response ...';
    btnText.style.display = 'block';
    loader.style.display = 'block';
    resultsArea.style.display = 'none';
    resultsArea.innerHTML = '';
    errorBox.style.display = 'none';
    ipDisplay.style.display = 'none';

    try {
        let ipv4Data = null;
        let ipv6Data = null;
        
        // Wenn spezifische IP-Version gewählt, nur diese checken
        if (ipVersion === 'ipv4' || ipVersion === 'ipv6') {
            let apiHost;
            
            if (ipVersion === 'ipv4') {
                apiHost = 'ipv4-cgnat.admon.me';
            } else {
                apiHost = 'ipv6-cgnat.admon.me';
            }
            
            const apiUrl = `https://${apiHost}/check?ports=${ports}&tls_analyze=true`;
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 25000);
            
            const response = await fetch(apiUrl, { signal: controller.signal });
            clearTimeout(timeoutId);
            
            let data;
            try {
                data = await response.json();
            } catch (e) {
                throw new Error(lolcatify("Service unavailable or response invalid. Please try again later."));
            }

            if (!response.ok) {
                throw new Error(lolcatify(data.message || data.error || 'Connection failed'));
            }
            
            const grouped = splitResultsByIPVersion(data);
            ipv4Data = grouped.ipv4Data;
            ipv6Data = grouped.ipv6Data;
            
            if (ipVersion === 'ipv4' && !ipv4Data && ipv6Data) {
                throw new Error(lolcatify("You requested an IPv4 test, but your connection was routed via IPv6. This happens when you don't have an IPv4 connection and Cloudflare proxies the request over IPv6. An IPv4 test cannot be performed."));
            }
            if (ipVersion === 'ipv6' && !ipv6Data && ipv4Data) {
                throw new Error(lolcatify("You requested an IPv6 test, but your connection was routed via IPv4. This happens when you don't have an IPv6 connection and Cloudflare proxies the request over IPv4. An IPv6 test cannot be performed."));
            }
        } else {
            // Beide IPv4 und IPv6 parallel checken
            const ipv4Host = 'ipv4-cgnat.admon.me';
            const ipv6Host = 'ipv6-cgnat.admon.me';
            
            const ipv4Url = `https://${ipv4Host}/check?ports=${ports}&tls_analyze=true`;
            const ipv6Url = `https://${ipv6Host}/check?ports=${ports}&tls_analyze=true`;
            
            // Parallel beide Requests starten
            const [ipv4Result, ipv6Result] = await Promise.allSettled([
                (async () => {
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), 25000);
                    try {
                        const response = await fetch(ipv4Url, { signal: controller.signal });
                        clearTimeout(timeoutId);
                        return await response.json();
                    } catch (e) {
                        clearTimeout(timeoutId);
                        throw e;
                    }
                })(),
                (async () => {
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), 25000);
                    try {
                        const response = await fetch(ipv6Url, { signal: controller.signal });
                        clearTimeout(timeoutId);
                        return await response.json();
                    } catch (e) {
                        clearTimeout(timeoutId);
                        throw e;
                    }
                })()
            ]);
            
            // Ergebnisse auswerten
            const grouped = splitResultsByIPVersion(
                ipv4Result.status === 'fulfilled' ? ipv4Result.value : null,
                ipv6Result.status === 'fulfilled' ? ipv6Result.value : null
            );
            ipv4Data = grouped.ipv4Data;
            ipv6Data = grouped.ipv6Data;
            
            // Wenn beide fehlschlagen, Fehler werfen
            if (!ipv4Data && !ipv6Data) {
                throw new Error(lolcatify('Both IPv4 and IPv6 checks failed'));
            }
        }

        // Render Results
        displayResults(ipv4Data, ipv6Data);

    } catch (err) {
        let msg = err.message;
        
        // Handle timeout errors
        if (err.name === 'AbortError') {
            msg = lolcatify("Request timeout! Server took too long to respond. 😿");
        }
        
        // Double check if some other weird error slipped through
        if (msg.toLowerCase().includes("unexpected token")) {
            msg = lolcatify("Service unavailable or response invalid. Please try again later.");
        }
        showError(msg);
    } finally {
        // Restore UI
        btn.disabled = false;
        if (ipVersion === 'ipv4') {
            btnText.textContent = lolcatMode ? '🌐 Test IPv4 only plz' : '🌐 Test IPv4 only';
        } else if (ipVersion === 'ipv6') {
            btnText.textContent = lolcatMode ? '🌐 Test IPv6 only plz' : '🌐 Test IPv6 only';
        } else {
            btnText.textContent = lolcatMode ? 'Check mah Reachability plz' : 'Check Reachability';
        }
        btnText.style.display = 'block';
        loader.style.display = 'none';
    }
}

function displayResults(ipv4Data, ipv6Data) {
    const resultsArea = document.getElementById('resultsArea');
    const ipDisplay = document.getElementById('ipDisplay');
    
    // IP-Adressen anzeigen
    let ipInfo = [];
    if (ipv4Data && ipv4Data.client_ip) {
        ipInfo.push(`IPv4: <strong>${ipv4Data.client_ip}</strong>`);
    }
    if (ipv6Data && ipv6Data.client_ip) {
        ipInfo.push(`IPv6: <strong>${ipv6Data.client_ip}</strong>`);
    }
    
    ipDisplay.className = 'client-ip';
    ipDisplay.innerHTML = `${lolcatify('Your Public IP')}: ${ipInfo.join(' | ')}`;
    ipDisplay.style.display = 'inline-block';

    // Alle Ports sammeln (IPv4 und IPv6)
    const allPorts = new Set();
    if (ipv4Data && ipv4Data.results) {
        Object.keys(ipv4Data.results).forEach(port => allPorts.add(port));
    }
    if (ipv6Data && ipv6Data.results) {
        Object.keys(ipv6Data.results).forEach(port => allPorts.add(port));
    }
    
    // Sort ports numerically
    const sortedPorts = Array.from(allPorts).sort((a, b) => parseInt(a) - parseInt(b));

    sortedPorts.forEach(port => {
        const ipv4Result = ipv4Data && ipv4Data.results ? ipv4Data.results[port] : null;
        const ipv6Result = ipv6Data && ipv6Data.results ? ipv6Data.results[port] : null;
        
        const item = document.createElement('div');
        item.className = 'result-item';

        let tlsContent = '';
        let sshContent = '';
        let expandButton = '';
        
        // Bestimme welches Result für TLS/SSH Details verwendet wird (bevorzuge IPv4)
        const primaryResult = ipv4Result || ipv6Result;

        // TLS Information
        if (primaryResult && primaryResult.tls) {
            const result = primaryResult;
            const cert = result.tls.certificate || {};
            const warnings = result.tls.warnings || [];
            
            let warningHtml = '';
            if (warnings.length > 0) {
                warningHtml = warnings.map(w => `<div class="tls-warning">⚠️ ${w.replace(/_/g, ' ')}</div>`).join('');
            }

            const notBefore = cert.not_before ? new Date(cert.not_before).toLocaleDateString() : 'N/A';
            const notAfter = cert.not_after ? new Date(cert.not_after).toLocaleDateString() : 'N/A';
            const daysLeft = cert.days_until_expiry !== undefined ? `${cert.days_until_expiry} days` : 'N/A';

            tlsContent = `
                <div class="result-details" id="details-${port}">
                    <div class="tls-info-grid">
                        <div class="tls-info-item">
                            <span class="tls-label">Version</span>
                            <span class="tls-value">${result.tls.version || 'Unknown'}</span>
                        </div>
                        <div class="tls-info-item">
                            <span class="tls-label">Cipher Suite</span>
                            <span class="tls-value">${result.tls.cipher_suite || 'Unknown'}</span>
                        </div>
                        <div class="tls-info-item">
                            <span class="tls-label">Subject</span>
                            <span class="tls-value">${cert.subject || 'N/A'}</span>
                        </div>
                         <div class="tls-info-item">
                            <span class="tls-label">Issuer</span>
                            <span class="tls-value">${cert.issuer || 'N/A'}</span>
                        </div>
                        <div class="tls-info-item">
                            <span class="tls-label">Validity</span>
                            <span class="tls-value">${notBefore} - ${notAfter}</span>
                        </div>
                         <div class="tls-info-item">
                            <span class="tls-label">Expires In</span>
                            <span class="tls-value">${daysLeft}</span>
                        </div>
                        ${cert.dns_names ? `
                        <div class="tls-info-item" style="grid-column: 1 / -1;">
                            <span class="tls-label">DNS Names</span>
                            <span class="tls-value">${cert.dns_names.join(', ')}</span>
                        </div>` : ''}
                        ${warningHtml ? `
                        <div class="tls-info-item" style="grid-column: 1 / -1;">
                             <span class="tls-label">Warnings</span>
                             ${warningHtml}
                        </div>` : ''}
                    </div>
                </div>
            `;
            
            expandButton = `
                <button class="expand-btn" onclick="toggleDetails('details-${port}', this)">
                    Details <span class="expand-icon">▼</span>
                </button>
            `;
        }

        // SSH/Banner Information
        // Check for direct banner field (new format) or SSH object (old format)
        const hasBanner = primaryResult && (primaryResult.banner || (primaryResult.ssh && primaryResult.ssh.banner));
        
        if (hasBanner) {
            const result = primaryResult;
            const banner = result.banner || result.ssh.banner;
            const ssh = result.ssh || {};
            const warnings = ssh.warnings || [];
            
            let warningHtml = '';
            if (warnings.length > 0) {
                warningHtml = warnings.map(w => `<div class="tls-warning">⚠️ ${w.replace(/_/g, ' ')}</div>`).join('');
            }

            // Build SSH info content
            let sshInfoItems = `
                <div class="tls-info-item">
                    <span class="tls-label">Banner</span>
                    <span class="tls-value">${banner}</span>
                </div>`;
            
            // Add SSH-specific fields if available
            if (ssh.protocol) {
                sshInfoItems += `
                <div class="tls-info-item">
                    <span class="tls-label">Protocol</span>
                    <span class="tls-value">${ssh.protocol}</span>
                </div>`;
            }
            
            if (ssh.software) {
                sshInfoItems += `
                <div class="tls-info-item">
                    <span class="tls-label">Software</span>
                    <span class="tls-value">${ssh.software}</span>
                </div>`;
            }
            
            if (ssh.host_key_algo) {
                sshInfoItems += `
                <div class="tls-info-item">
                    <span class="tls-label">Host Key</span>
                    <span class="tls-value">${ssh.host_key_algo}</span>
                </div>`;
            }
            
            if (warningHtml) {
                sshInfoItems += `
                <div class="tls-info-item" style="grid-column: 1 / -1;">
                     <span class="tls-label">Warnings</span>
                     ${warningHtml}
                </div>`;
            }

            sshContent = `
                <div class="result-details" id="details-${port}">
                    <div class="tls-info-grid">
                        ${sshInfoItems}
                    </div>
                </div>
            `;
            
            expandButton = `
                <button class="expand-btn" onclick="toggleDetails('details-${port}', this)">
                    Details <span class="expand-icon">▼</span>
                </button>
            `;
        }

        let tlsBadge = '';
        if (primaryResult && primaryResult.tls) {
            tlsBadge = `<span class="tls-badge">TLS</span>`;
        }
        
        let sshBadge = '';
        // Show SSH badge if we have banner or SSH info
        if (primaryResult && (primaryResult.banner || primaryResult.ssh)) {
            sshBadge = `<span class="ssh-badge">SSH</span>`;
        }
        
        // Status für beide IP-Versionen
        let statusHtml = '';
        let resultInfo = '';
        
        if (ipv4Result && ipv6Result) {
            // Beide verfügbar
            const ipv4Status = ipv4Result.reachable ? '✅' : '❌';
            const ipv6Status = ipv6Result.reachable ? '✅' : '❌';
            statusHtml = `
                <div class="status-dual">
                    <span class="status-label">IPv4: ${ipv4Status}</span>
                    <span class="status-label">IPv6: ${ipv6Status}</span>
                </div>
            `;
            
            // Info generieren basierend auf Kombination
            if (ipv4Result.reachable && ipv6Result.reachable) {
                resultInfo = lolcatify('🎉 Perfect! Reachable via both IPv4 and IPv6. Your service is accessible from anywhere.');
            } else if (ipv4Result.reachable && !ipv6Result.reachable) {
                resultInfo = lolcatify('⚠️ Only reachable via IPv4. IPv6 might be blocked or not configured properly.');
            } else if (!ipv4Result.reachable && ipv6Result.reachable) {
                resultInfo = lolcatify('⚠️ Only reachable via IPv6. IPv4 appears to be blocked (possibly CGNAT or firewall).');
            } else {
                resultInfo = lolcatify('❌ Not reachable via IPv4 or IPv6. Check port forwarding, firewall rules, or CGNAT issues.');
            }
        } else if (ipv4Result) {
            // Nur IPv4
            const isReachable = ipv4Result.reachable;
            statusHtml = `
                <div class="status ${isReachable ? 'reachable' : 'unreachable'}">
                    IPv4: ${isReachable ? 'Reachable' : 'Unreachable'}
                </div>
            `;
            
            if (isReachable) {
                resultInfo = lolcatify('✅ Reachable via IPv4.');
            } else {
                resultInfo = lolcatify('❌ Not reachable via IPv4. Check port forwarding or firewall settings.');
            }
        } else if (ipv6Result) {
            // Nur IPv6
            const isReachable = ipv6Result.reachable;
            statusHtml = `
                <div class="status ${isReachable ? 'reachable' : 'unreachable'}">
                    IPv6: ${isReachable ? 'Reachable' : 'Unreachable'}
                </div>
            `;
            
            if (isReachable) {
                resultInfo = lolcatify('✅ Reachable via IPv6.');
            } else {
                resultInfo = lolcatify('❌ Not reachable via IPv6. Check port forwarding or firewall settings.');
            }
        }

        item.innerHTML = `
            <div class="result-header">
                <div class="port-info">
                    <span class="port-number">Port ${port}</span>
                    ${tlsBadge}
                    ${sshBadge}
                    ${expandButton}
                </div>
                ${statusHtml}
            </div>
            ${resultInfo ? `<div class="result-info">${resultInfo}</div>` : ''}
            ${tlsContent}
            ${sshContent}
        `;
        resultsArea.appendChild(item);
    });

    resultsArea.style.display = 'block';
}

window.toggleDetails = function(id, btn) {
    console.log("Toggling details for:", id);
    const details = document.getElementById(id);
    if (!details) {
        console.error("Details element not found:", id);
        return;
    }
    
    details.classList.toggle('open');
    const isOpen = details.classList.contains('open');
    
    // Find the result-item container (grand-grand-parent of button)
    // Structure: result-item > result-header > port-info > button
    const resultItem = btn.closest('.result-item');
    if (resultItem) {
        if (isOpen) {
            resultItem.classList.add('open');
        } else {
            resultItem.classList.remove('open');
        }
    }
}

function showError(msg) {
    const errorBox = document.getElementById('errorBox');
    errorBox.textContent = msg;
    errorBox.style.display = 'block';
}

// LOLcat Mode - Activate with ?lolcat in URL
let lolcatMode = false;

function initLolcatMode() {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('lolcat')) {
        lolcatMode = true;
        
        // Apply LOLcat transformations
        const translations = {
            'h1': 'Can I haz Reachability?',
            '.subtitle': 'Check if ur device can has internets from teh outside.',
            '.options-label': 'Pick teh Ports 2 Check',
            '.btn-text': 'Check mah Reachability plz',
            '.faq-title': 'Questionz U Might Has',
            'title': 'Can I haz Reachability?'
        };
        
        // Update texts
        Object.keys(translations).forEach(selector => {
            const element = document.querySelector(selector);
            if (element) {
                if (selector === 'title') {
                    element.textContent = translations[selector];
                } else {
                    element.textContent = translations[selector];
                }
            }
        });
        
        // Update IPv4/IPv6 buttons
        const ipv4Btn = document.querySelector('#checkIPv4Btn .btn-text');
        const ipv6Btn = document.querySelector('#checkIPv6Btn .btn-text');
        if (ipv4Btn) ipv4Btn.textContent = '🌐 Test IPv4 only plz';
        if (ipv6Btn) ipv6Btn.textContent = '🌐 Test IPv6 only plz';
        
        // Update FAQ questions and answers
        const faqItems = document.querySelectorAll('.faq-item');
        const lolcatFAQs = [
            {
                question: 'Y mah port no work? 😿',
                answer: 'Common reasons be like:<ul><li>U iz behind Carrier-Grade NAT (CGNAT) - big sadz</li><li>Port forwardin not setup on ur router</li><li>Firewall on ur device blockin teh connectionz</li><li>Ur ISP blocks ports (like 80/443) - no fun allowd</li></ul>'
            },
            {
                question: 'Iz dis safe? 🐱',
                answer: 'Oh yez! We only try 2 connect 2 teh IP that askd us. We cant scan random IPs. Teh connection try iz harmless and only checks if TCP handshake can haz happen.'
            },
            {
                question: 'Wut iz TLS thingy? 🔐',
                answer: 'If Port 443 can haz reachability, we look at ur SSL/TLS certificate 2 show u details like if itz valid, who made it, and if u has problemz (like expired certs or weak ciphers - no gud!).'
            },
            {
                question: 'U keepin mah IPs? 👀',
                answer: 'IP addresses r temporarily stored in logs 4 technical stuffz, but we anonymize dem by removing teh last octet (like 192.168.1.xxx). Dis ensures privacy while allowing basic diagnosticz. 4 IPv6, teh last 80 bits r zeroed out. We protec ur privacy!'
            }
        ];
        
        faqItems.forEach((item, index) => {
            if (lolcatFAQs[index]) {
                const summary = item.querySelector('summary');
                const answer = item.querySelector('.faq-a');
                if (summary) summary.textContent = lolcatFAQs[index].question;
                if (answer) answer.innerHTML = lolcatFAQs[index].answer;
            }
        });
        
        // Add cat emoji to icon
        const icon = document.querySelector('.icon');
        if (icon) {
            icon.textContent = '😺';
        }
        
        // Update wizard button
        const wizardBtn = document.querySelector('.wizard-btn .btn-text');
        if (wizardBtn) {
            wizardBtn.textContent = '🧭 Step-by-Step Test (4 Catz)';
        }
    }
}

function lolcatify(text) {
    if (!lolcatMode) return text;
    
    const translations = {
        'Please select at least one port to check.': 'Plz pick at least 1 port 2 check, kthx!',
        'Service unavailable or response invalid. Please try again later.': 'Service no work or response iz weird. Plz try again latr! 😿',
        'Connection failed': 'Connection failz! No can connect 😢',
        'Your Public IP': 'Ur Public IP',
        'Request timeout! Server took too long to respond. 😿': 'Request timeout! Server took 2 long 2 respond. 😿',
        '🎉 Perfect! Reachable via both IPv4 and IPv6. Your service is accessible from anywhere.': '🎉 Purrfect! Can reach via both IPv4 and IPv6. Ur service iz accessible from anywher! 😻',
        '⚠️ Only reachable via IPv4. IPv6 might be blocked or not configured properly.': '⚠️ Only reachable via IPv4. IPv6 mite be blocked or not configured properly. 😿',
        '⚠️ Only reachable via IPv6. IPv4 appears to be blocked (possibly CGNAT or firewall).': '⚠️ Only reachable via IPv6. IPv4 appears 2 be blocked (possibly CGNAT or firewall). 😿',
        '❌ Not reachable via IPv4 or IPv6. Check port forwarding, firewall rules, or CGNAT issues.': '❌ Not reachable via IPv4 or IPv6. Check port forwardin, firewall rulez, or CGNAT issues. 🙀',
        '✅ Reachable via IPv4.': '✅ Reachable via IPv4. Yay! 😺',
        '❌ Not reachable via IPv4. Check port forwarding or firewall settings.': '❌ Not reachable via IPv4. Check port forwardin or firewall settings. 😿',
        '✅ Reachable via IPv6.': '✅ Reachable via IPv6. Yay! 😺',
        '❌ Not reachable via IPv6. Check port forwarding or firewall settings.': '❌ Not reachable via IPv6. Check port forwardin or firewall settings. 😿'
    };
    
    return translations[text] || text;
}

// Initialize LOLcat mode on page load
document.addEventListener('DOMContentLoaded', initLolcatMode);

// ============================================================================
// Wizard Functionality
// ============================================================================

let currentWizardStep = 1;
const totalWizardSteps = 5;

const wizardSteps = {
    1: {
        title: 'Welcome to the Router Test Wizard',
        titleLolcat: 'Welcomez 2 teh Router Test Wizard 😺',
        content: `
            <h3>🎯 Test Your Router's Reachability</h3>
            <p>This step-by-step guide will help you test if your GL.iNet router is accessible from the internet.</p>
            
            <div class="info-box">
                <p><strong>What you'll need:</strong></p>
                <ul>
                    <li>SSH access to your GL.iNet router</li>
                    <li>Root password for your router</li>
                    <li>About 5 minutes of time</li>
                </ul>
            </div>
            
            <div class="warning-box">
                <p><strong>⚠️ Important:</strong> This wizard will temporarily open firewall ports on your router for testing. The ports will be automatically closed after the test or after 5 minutes.</p>
            </div>
            
            <div class="warning-box" style="margin-top: 1rem;">
                <p><strong>🚫 VPN Users:</strong> The manual web test (Step 4) will NOT work if you're connected via VPN! Your VPN connection will test the VPN server's IP instead of your router. Use the <strong>--auto-test</strong> option instead, which runs directly on your router.</p>
            </div>
            
            <p><strong>How it works:</strong></p>
            <ol>
                <li>You'll connect to your router via SSH</li>
                <li>Run a test script that temporarily opens the firewall</li>
                <li>Test the reachability from this website</li>
                <li>The script automatically closes the firewall again</li>
            </ol>
        `,
        contentLolcat: `
            <h3>🎯 Test Ur Router's Reachability plz</h3>
            <p>Dis step-by-step guide will halp u test if ur GL.iNet router can haz internets from teh outside.</p>
            
            <div class="info-box">
                <p><strong>Wut u need 4 dis:</strong></p>
                <ul>
                    <li>SSH access 2 ur GL.iNet router (fancy!)</li>
                    <li>Root password 4 ur router (sekrit!)</li>
                    <li>Bout 5 minutez of ur time (not 2 long!)</li>
                </ul>
            </div>
            
            <div class="warning-box">
                <p><strong>⚠️ Importantz:</strong> Dis wizard will temporarily open firewall ports on ur router 4 testin. Teh ports will be automatically closd aftr teh test or aftr 5 minutez. No worryz!</p>
            </div>
            
            <div class="warning-box" style="margin-top: 1rem;">
                <p><strong>🚫 VPN Userz:</strong> Teh manual web test (Step 4) will NOT werk if ur connected via VPN! Ur VPN connection will test teh VPN server's IP instead of ur router. Use teh <strong>--auto-test</strong> option instead, which runz directly on ur router. Much bettar! 😺</p>
            </div>
            
            <p><strong>How dis werkz:</strong></p>
            <ol>
                <li>U'll connect 2 ur router via SSH (so pro!)</li>
                <li>Run test script dat temporarily openz teh firewall</li>
                <li>Test teh reachability from dis website</li>
                <li>Teh script automatically closez teh firewall again (safe!)</li>
            </ol>
        `
    },
    2: {
        title: 'Step 1: Connect to Your Router',
        titleLolcat: 'Step 1: Connect 2 Ur Router 🔌',
        content: `
            <h3>🔌 Establish SSH Connection</h3>
            <p>First, you need to connect to your router via SSH. Use one of the following methods:</p>
            
            <p><strong>Method 1: Using Terminal (macOS/Linux)</strong></p>
            <div class="code-block">
                <button class="copy-btn" onclick="copyCode(this, 'ssh root@192.168.8.1')">📋 Copy</button>
                <code>ssh root@192.168.8.1</code>
            </div>
            
            <p><strong>Method 2: Using PuTTY (Windows)</strong></p>
            <ol>
                <li>Download and open <a href="https://www.putty.org/" target="_blank">PuTTY</a></li>
                <li>Enter your router's IP address: <code>192.168.8.1</code></li>
                <li>Click "Open" and log in with username <code>root</code></li>
            </ol>
            
            <div class="info-box">
                <p><strong>💡 Tip:</strong> If your router uses a different IP address, you can find it in your router's admin panel or use <code>ifconfig</code> on your computer to find the gateway IP.</p>
            </div>
            
            <p>When prompted, enter your root password. If you haven't changed it, check your router's documentation for the default password.</p>
        `,
        contentLolcat: `
            <h3>🔌 Establish SSH Connection (fancy stuff!)</h3>
            <p>First, u need 2 connect 2 ur router via SSH. Use 1 of dese methods plz:</p>
            
            <p><strong>Method 1: Usin Terminal (macOS/Linux) - 4 teh pros</strong></p>
            <div class="code-block">
                <button class="copy-btn" onclick="copyCode(this, 'ssh root@192.168.8.1')">📋 Copy dis</button>
                <code>ssh root@192.168.8.1</code>
            </div>
            
            <p><strong>Method 2: Usin PuTTY (Windows) - also gud</strong></p>
            <ol>
                <li>Download and open <a href="https://www.putty.org/" target="_blank">PuTTY</a> (iz free!)</li>
                <li>Enter ur router's IP address: <code>192.168.8.1</code></li>
                <li>Click "Open" and log in wif username <code>root</code></li>
            </ol>
            
            <div class="info-box">
                <p><strong>💡 Protip:</strong> If ur router usez different IP address, u can findz it in ur router's admin panel or use <code>ifconfig</code> on ur computr 2 find teh gateway IP. Ez!</p>
            </div>
            
            <p>Wen promptd, enter ur root password. If u havent changd it, check ur router's documentation 4 teh default password. Dont use "password123" plz! 😹</p>
        `
    },
    3: {
        title: 'Step 2: Run the Test Script',
        titleLolcat: 'Step 2: Run teh Test Script 🚀',
        content: `
            <h3>🚀 Execute the Firewall Test Script</h3>
            <p>Now that you're connected, you have two options to test your router:</p>
            
            <h4 style="color: var(--primary); margin-top: 1.5rem;">Option 1: Automatic Test (Recommended)</h4>
            <p>The script will automatically open the firewall, test it, and close it again - all in one command!</p>
            
            <div class="code-block">
                <button class="copy-btn" onclick="copyCode(this, 'curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --auto-test')">📋 Copy</button>
                <code>curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --auto-test</code>
            </div>
            
            <div class="success-box">
                <p><strong>✨ This is the easiest way!</strong> The script will show you the results directly in your terminal and automatically clean up afterwards.</p>
            </div>
            
            <h4 style="color: var(--primary); margin-top: 2rem;">Option 2: Manual Test</h4>
            <p>For manual testing through this website, use this command:</p>
            
            <div class="code-block">
                <button class="copy-btn" onclick="copyCode(this, 'curl -sSL https://cgnat.admon.me/test.sh | sh')">📋 Copy</button>
                <code>curl -sSL https://cgnat.admon.me/test.sh | sh</code>
            </div>
            
            <p style="margin-top: 1rem;"><strong>What the script does:</strong></p>
            <ul>
                <li>Checks your current firewall configuration</li>
                <li>Temporarily opens ports 80 and 443 for testing</li>
                <li><strong>Auto mode:</strong> Runs the test automatically and shows results</li>
                <li><strong>Manual mode:</strong> Waits for you to test (or 5 minutes timeout)</li>
                <li>Automatically restores your firewall to its previous state</li>
            </ul>
            
            <div class="warning-box">
                <p><strong>⚠️ Security Note:</strong> The script will only open the firewall if it was previously closed. If your firewall was already open, it will remain open after the test.</p>
            </div>
            
            <details style="margin-top: 2rem;">
                <summary style="cursor: pointer; font-weight: 600; color: var(--primary); padding: 0.75rem 0; font-size: 1rem;">🔧 Advanced Options (Click to expand)</summary>
                <div style="margin-top: 1rem;">
                    <p><strong>Test specific ports:</strong></p>
                    <div class="code-block">
                        <button class="copy-btn" onclick="copyCode(this, 'curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --ports 8080,8443 --auto-test')">📋 Copy</button>
                        <code>curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --ports 8080,8443 --auto-test</code>
                    </div>
                    
                    <p><strong>Custom timeout (manual mode):</strong></p>
                    <div class="code-block">
                        <button class="copy-btn" onclick="copyCode(this, 'curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --timeout 600')">📋 Copy</button>
                        <code>curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --timeout 600</code>
                    </div>
                    
                    <p><strong>Cleanup only:</strong></p>
                    <div class="code-block">
                        <button class="copy-btn" onclick="copyCode(this, 'curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --cleanup')">📋 Copy</button>
                        <code>curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --cleanup</code>
                    </div>
                </div>
            </details>
        `,
        contentLolcat: `
            <h3>🚀 Execute teh Firewall Test Script</h3>
            <p>Now dat ur connected, u haz 2 options 2 test ur router:</p>
            
            <h4 style="color: var(--primary); margin-top: 1.5rem;">Option 1: Automatic Test (Recommended 4 lazy catz 😺)</h4>
            <p>Teh script will automatically open teh firewall, test it, and close it again - all in 1 command! So ez!</p>
            
            <div class="code-block">
                <button class="copy-btn" onclick="copyCode(this, 'curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --auto-test')">📋 Copy dis magik</button>
                <code>curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --auto-test</code>
            </div>
            
            <div class="success-box">
                <p><strong>✨ Dis iz teh easiest way!</strong> Teh script will show u teh results directly in ur terminal and automatically clean up afterwards. No manual werk! Purrfect! 🐱</p>
            </div>
            
            <h4 style="color: var(--primary); margin-top: 2rem;">Option 2: Manual Test (4 control freakz)</h4>
            <p>4 manual testin thru dis website, use dis command:</p>
            
            <div class="code-block">
                <button class="copy-btn" onclick="copyCode(this, 'curl -sSL https://cgnat.admon.me/test.sh | sh')">📋 Copy</button>
                <code>curl -sSL https://cgnat.admon.me/test.sh | sh</code>
            </div>
            
            <p style="margin-top: 1rem;"><strong>Wut teh script doez:</strong></p>
            <ul>
                <li>Checks ur current firewall configuration (safe!)</li>
                <li>Temporarily openz ports 80 and 443 4 testin</li>
                <li><strong>Auto mode:</strong> Runs teh test automatically and showz results (wow!)</li>
                <li><strong>Manual mode:</strong> Waits 4 u 2 test (or 5 minutez timeout)</li>
                <li>Automatically restorez ur firewall 2 itz previous state (phew!)</li>
            </ul>
            
            <div class="warning-box">
                <p><strong>⚠️ Security Note:</strong> Teh script will only open teh firewall if it waz previously closd. If ur firewall waz already open, it will remain open aftr teh test. No surprisez!</p>
            </div>
            
            <details style="margin-top: 2rem;">
                <summary style="cursor: pointer; font-weight: 600; color: var(--primary); padding: 0.75rem 0; font-size: 1rem;">🔧 Advanced Optionz (4 power userz - click 2 expand)</summary>
                <div style="margin-top: 1rem;">
                    <p><strong>Test specific ports:</strong></p>
                    <div class="code-block">
                        <button class="copy-btn" onclick="copyCode(this, 'curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --ports 8080,8443 --auto-test')">📋 Copy dis</button>
                        <code>curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --ports 8080,8443 --auto-test</code>
                    </div>
                    
                    <p><strong>Custom timeout (manual mode):</strong></p>
                    <div class="code-block">
                        <button class="copy-btn" onclick="copyCode(this, 'curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --timeout 600')">📋 Copy dis</button>
                        <code>curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --timeout 600</code>
                    </div>
                    
                    <p><strong>Cleanup only:</strong></p>
                    <div class="code-block">
                        <button class="copy-btn" onclick="copyCode(this, 'curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --cleanup')">📋 Copy dis</button>
                        <code>curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --cleanup</code>
                    </div>
                </div>
            </details>
            
            <p style="margin-top: 1.5rem;">Aftr runnin teh command, u'll see teh firewall status and test results (in auto mode) or instructions 2 continue (in manual mode). Much info! 😸</p>
        `
    },
    4: {
        title: 'Step 3: Review Results',
        titleLolcat: 'Step 3: Review Ur Results ✅',
        content: `
            <h3>✅ Test Results & Next Steps</h3>
            
            <div class="info-box">
                <p><strong>If you used --auto-test:</strong></p>
                <p>You should already see the test results in your SSH terminal! The firewall has been automatically closed.</p>
            </div>
            
            <div class="warning-box">
                <p><strong>If you used manual mode:</strong></p>
                <p>Click the button below to test, then return to your SSH terminal and press ENTER to close the firewall.</p>
            </div>
            
            <div class="warning-box" style="margin-top: 1rem;">
                <p><strong>🚫 Important for VPN Users:</strong></p>
                <p>If you're currently connected via VPN, this web-based test will check the VPN server's reachability, NOT your router! Disconnect from VPN before testing, or use the <strong>--auto-test</strong> option which runs directly on the router.</p>
            </div>
            
            <h4 style="margin-top: 2rem;">Manual Test (Optional)</h4>
            <p>Only use this if you ran the script in manual mode (without --auto-test):</p>
            
            <button id="wizardTestBtn" onclick="runTestFromWizard()" class="btn-primary" style="width: 100%; margin: 1.5rem 0; padding: 1.25rem;">
                🔍 Run Manual Reachability Test
            </button>
            
            <div id="wizardTestResults" style="margin-top: 1.5rem;"></div>
            
            <h4 style="margin-top: 2rem;">Understanding Your Results</h4>
            
            <div class="success-box">
                <p><strong>✅ Green "Reachable"</strong></p>
                <p>Congratulations! Your router is accessible from the internet. You can host services on these ports.</p>
            </div>
            
            <div class="warning-box">
                <p><strong>❌ Red "Unreachable"</strong></p>
                <p>Your router cannot be reached from the internet. Common causes:</p>
                <ul>
                    <li><strong>CGNAT:</strong> You're behind Carrier-Grade NAT (check with your ISP)</li>
                    <li><strong>Port Forwarding:</strong> Not configured in your router settings</li>
                    <li><strong>ISP Blocking:</strong> Your ISP blocks incoming connections on these ports</li>
                    <li><strong>Additional Firewalls:</strong> Network-level firewalls blocking traffic</li>
                </ul>
            </div>
            
            <h4 style="margin-top: 2rem;">Next Steps</h4>
            <ul>
                <li><strong>If ports are reachable:</strong> You can now set up services like web servers, VPNs, or use ACME/Let's Encrypt</li>
                <li><strong>If ports are unreachable:</strong> Check the FAQ section below for troubleshooting tips</li>
                <li><strong>For ACME/Let's Encrypt:</strong> Check out the <a href="https://github.com/admonstrator/glinet-enable-acme" target="_blank">glinet-enable-acme</a> project</li>
            </ul>
            
            <div class="info-box" style="margin-top: 2rem;">
                <p><strong>💡 Remember:</strong> If you used manual mode, don't forget to press ENTER in your SSH terminal to close the firewall!</p>
            </div>
        `,
        contentLolcat: `
            <h3>✅ Test Results & Next Stepz</h3>
            
            <div class="info-box">
                <p><strong>If u usd --auto-test:</strong></p>
                <p>U should already see teh test results in ur SSH terminal! Teh firewall has been automatically closd. Much convenient! 😺</p>
            </div>
            
            <div class="warning-box">
                <p><strong>If u usd manual mode:</strong></p>
                <p>Click teh button below 2 test, then return 2 ur SSH terminal and press ENTER 2 close teh firewall. Dont 4get!</p>
            </div>
            
            <div class="warning-box" style="margin-top: 1rem;">
                <p><strong>🚫 Importantz 4 VPN Userz:</strong></p>
                <p>If ur currently connected via VPN, dis web-based test will check teh VPN server's reachability, NOT ur router! Disconnect from VPN before testin, or use teh <strong>--auto-test</strong> option which runz directly on teh router. Much smartar! 🧠</p>
            </div>
            
            <h4 style="margin-top: 2rem;">Manual Test (Optional - only if u needz)</h4>
            <p>Only use dis if u ran teh script in manual mode (without --auto-test):</p>
            
            <button id="wizardTestBtn" onclick="runTestFromWizard()" class="btn-primary" style="width: 100%; margin: 1.5rem 0; padding: 1.25rem;">
                🔍 Run Manual Reachability Test Plz
            </button>
            
            <div id="wizardTestResults" style="margin-top: 1.5rem;"></div>
            
            <h4 style="margin-top: 2rem;">Understandin Ur Results (wut dey mean)</h4>
            
            <div class="success-box">
                <p><strong>✅ Green "Reachable" - YAAAY!</strong></p>
                <p>Congratulationz! Ur router iz accessible from teh internets. U can host servicez on dese ports. Much successz! 🎉</p>
            </div>
            
            <div class="warning-box">
                <p><strong>❌ Red "Unreachable" - oh noes! 😿</strong></p>
                <p>Ur router cannot be reachd from teh internets. Common causez:</p>
                <ul>
                    <li><strong>CGNAT:</strong> Ur behind Carrier-Grade NAT (check wif ur ISP - dey might haz u trapped!)</li>
                    <li><strong>Port Forwardin:</strong> Not configurd in ur router settingz (needz setup!)</li>
                    <li><strong>ISP Blockin:</strong> Ur ISP blockz incomin connectionz on dese ports (mean ISP!)</li>
                    <li><strong>Additional Firewallz:</strong> Network-level firewallz blockin traffic (2 many firewallz!)</li>
                </ul>
            </div>
            
            <h4 style="margin-top: 2rem;">Next Stepz (wut 2 do now)</h4>
            <ul>
                <li><strong>If ports r reachable:</strong> U can now set up servicez like web serverz, VPNs, or use ACME/Let's Encrypt! Wow such hosting! 🌐</li>
                <li><strong>If ports r unreachable:</strong> Check teh FAQ section below 4 troubleshootin tips. Dont give up! 💪</li>
                <li><strong>4 ACME/Let's Encrypt:</strong> Check out teh <a href="https://github.com/admonstrator/glinet-enable-acme" target="_blank">glinet-enable-acme</a> project 4 free SSL certificates! So secure!</li>
            </ul>
            
            <div class="info-box" style="margin-top: 2rem;">
                <p><strong>💡 Remembr:</strong> If u usd manual mode, dont 4get 2 press ENTER in ur SSH terminal 2 close teh firewall! Important! 🔐</p>
            </div>
        `
    },
    5: {
        title: 'Support This Project',
        titleLolcat: 'Support Dis Project 💖',
        content: `
            <h3>🙏 Thank You for Using This Tool!</h3>
            <p>This service is provided completely <strong>free of charge</strong> and is open source. If you found it helpful, please consider supporting the development!</p>
            
            <details style="margin-top: 1.5rem;">
                <summary style="cursor: pointer; font-weight: 600; color: var(--primary); padding: 0.75rem 0; font-size: 1rem;">🧑‍💻 Who is Admon? (Click to learn more)</summary>
                <div class="info-box" style="margin-top: 1rem;">
                    <p><strong>Admon</strong> is the guy who goes above and beyond for the GL.iNet community! As an <strong>official forum moderator</strong>, <strong>beta tester</strong>, and <a href="https://forum.gl-inet.com/u/admon/summary" target="_blank">active community member</a>, he develops free open-source tools that make GL.iNet routers even better. Known for his love of seals 🦭, direct communication, and the philosophy: "You can definitely automate everything."</p>
                    
                    <p style="margin-top: 1rem;"><strong>His most popular tools:</strong></p>
                    <ul style="margin-top: 0.5rem;">
                        <li><strong>🦭 <a href="https://github.com/admonstrator/glinet-tailscale-updater" target="_blank">Tailscale Updater</a>:</strong> Keep Tailscale up-to-date (400+ GitHub stars)</li>
                        <li><strong>🛡️ <a href="https://github.com/admonstrator/glinet-adguard-updater" target="_blank">AdGuard Home Updater</a>:</strong> Update AdGuard Home while preserving settings</li>
                        <li><strong>🔐 <a href="https://github.com/admonstrator/glinet-enable-acme" target="_blank">ACME Certificate Manager</a>:</strong> Free SSL/TLS certificates for your router</li>
                        <li><strong>💬 <a href="https://github.com/admonstrator/glinet-toolbox" target="_blank">GL.iNet Toolbox</a>:</strong> Curated scripts and troubleshooting guides</li>
                    </ul>
                    
                    <p style="margin-top: 1rem; font-size: 0.9rem;">All tools are tested on real hardware and trusted by the GL.iNet community worldwide.</p>
                </div>
            </details>
            
            <div class="success-box">
                <p><strong>✨ What your support enables:</strong></p>
                <ul>
                    <li>Keeping the service online and maintained</li>
                    <li>Development of new features</li>
                    <li>More tools for the GL.iNet community</li>
                    <li>Server costs and infrastructure</li>
                    <li>Energy drinks, cookies, and therapy 😅</li>
                </ul>
            </div>
            
            <h4 style="margin-top: 2rem; text-align: center; color: var(--primary);">Choose Your Preferred Platform</h4>
            
            <div style="display: flex; flex-direction: column; gap: 1rem; margin: 2rem 0;">
                <a href="https://github.com/sponsors/admonstrator" target="_blank" style="text-decoration: none;">
                    <img src="https://img.shields.io/badge/GitHub-Sponsors-EA4AAA?style=for-the-badge&logo=github" alt="GitHub Sponsors" style="width: 100%; max-width: 180px; margin: 0 auto; display: block;">
                </a>
                <a href="https://buymeacoffee.com/admon" target="_blank" style="text-decoration: none;">
                    <img src="https://img.shields.io/badge/Buy%20Me%20A%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black" alt="Buy Me A Coffee" style="width: 100%; max-width: 180px; margin: 0 auto; display: block;">
                </a>
                <a href="https://ko-fi.com/admon" target="_blank" style="text-decoration: none;">
                    <img src="https://img.shields.io/badge/Ko--fi-FF5E5B?style=for-the-badge&logo=ko-fi&logoColor=white" alt="Ko-fi" style="width: 100%; max-width: 180px; margin: 0 auto; display: block;">
                </a>
                <a href="https://link.admon.me/paypal" target="_blank" style="text-decoration: none;">
                    <img src="https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white" alt="PayPal" style="width: 100%; max-width: 180px; margin: 0 auto; display: block;">
                </a>
            </div>
            
            <div class="info-box" style="margin-top: 2rem;">
                <p><strong>👍 Can't donate right now?</strong></p>
                <p>No worries! You can also help by:</p>
                <ul>
                    <li>⭐ Starring the project on GitHub</li>
                    <li>📢 Sharing this tool with others</li>
                    <li>🐛 Reporting bugs or suggesting features</li>
                    <li>📝 Contributing to the documentation</li>
                </ul>
            </div>
            
            <p style="text-align: center; margin-top: 2rem; color: var(--text-light);">Thank you for being awesome! 🎉</p>
        `,
        contentLolcat: `
            <h3>🙏 Thank U 4 Using Dis Tool!</h3>
            <p>Dis service iz provided completely <strong>free of charge</strong> and iz open source. If u found it helpful, plz consider supporting teh development! Much appreciate! 💖</p>
            
            <details style="margin-top: 1.5rem;">
                <summary style="cursor: pointer; font-weight: 600; color: var(--primary); padding: 0.75rem 0; font-size: 1rem;">🧑‍💻 Who iz Admon? (Click 2 learn moar)</summary>
                <div class="info-box" style="margin-top: 1rem;">
                    <p><strong>Admon</strong> iz teh guy who goez above and beyond 4 teh GL.iNet community! As an <strong>official forum moderator</strong>, <strong>beta tester</strong>, and <a href="https://forum.gl-inet.com/u/admon/summary" target="_blank">active community member</a>, he develops free open-source toolz dat make GL.iNet routerz even bettar. Known 4 his love of seals 🦭, direct communication, and teh philosophy: "U can definitely automate everything." Such dedication! 🌟</p>
                    
                    <p style="margin-top: 1rem;"><strong>His most popular toolz:</strong></p>
                    <ul style="margin-top: 0.5rem;">
                        <li><strong>🦭 <a href="https://github.com/admonstrator/glinet-tailscale-updater" target="_blank">Tailscale Updater</a>:</strong> Keep Tailscale up-to-date (400+ GitHub starz!)</li>
                        <li><strong>🛡️ <a href="https://github.com/admonstrator/glinet-adguard-updater" target="_blank">AdGuard Home Updater</a>:</strong> Update AdGuard Home while preserving settingz</li>
                        <li><strong>🔐 <a href="https://github.com/admonstrator/glinet-enable-acme" target="_blank">ACME Certificate Manager</a>:</strong> Free SSL/TLS certificates 4 ur router</li>
                        <li><strong>💬 <a href="https://github.com/admonstrator/glinet-toolbox" target="_blank">GL.iNet Toolbox</a>:</strong> Curated scripts and troubleshootin guidez</li>
                    </ul>
                    
                    <p style="margin-top: 1rem; font-size: 0.9rem;">All toolz r tested on real hardware and trusted by teh GL.iNet community worldwide. Much wow! 🎉</p>
                </div>
            </details>
            
            <div class="success-box">
                <p><strong>✨ Wut ur support enablez:</strong></p>
                <ul>
                    <li>Keeping teh service online and maintained (so it workz!)</li>
                    <li>Development of new featurez (moar cool stuff!)</li>
                    <li>More tools 4 teh GL.iNet community (halp evry1!)</li>
                    <li>Server costs and infrastructure (expensive! 💸)</li>
                    <li>Energy drinkz, cookiez, and therapy 😅</li>
                </ul>
            </div>
            
            <h4 style="margin-top: 2rem; text-align: center; color: var(--primary);">Choose Ur Preferred Platform plz</h4>
            
            <div style="display: flex; flex-direction: column; gap: 1rem; margin: 2rem 0;">
                <a href="https://github.com/sponsors/admonstrator" target="_blank" style="text-decoration: none;">
                    <img src="https://img.shields.io/badge/GitHub-Sponsors-EA4AAA?style=for-the-badge&logo=github" alt="GitHub Sponsors" style="width: 100%; max-width: 180px; margin: 0 auto; display: block;">
                </a>
                <a href="https://buymeacoffee.com/admon" target="_blank" style="text-decoration: none;">
                    <img src="https://img.shields.io/badge/Buy%20Me%20A%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black" alt="Buy Me A Coffee" style="width: 100%; max-width: 180px; margin: 0 auto; display: block;">
                </a>
                <a href="https://ko-fi.com/admon" target="_blank" style="text-decoration: none;">
                    <img src="https://img.shields.io/badge/Ko--fi-FF5E5B?style=for-the-badge&logo=ko-fi&logoColor=white" alt="Ko-fi" style="width: 100%; max-width: 180px; margin: 0 auto; display: block;">
                </a>
                <a href="https://link.admon.me/paypal" target="_blank" style="text-decoration: none;">
                    <img src="https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white" alt="PayPal" style="width: 100%; max-width: 180px; margin: 0 auto; display: block;">
                </a>
            </div>
            
            <div class="info-box" style="margin-top: 2rem;">
                <p><strong>👍 Cant donate right now?</strong></p>
                <p>No worryz! U can also halp by:</p>
                <ul>
                    <li>⭐ Starring teh project on <a href="https://github.com/admonstrator/can-i-haz-reachability" target="_blank">GitHub</a></li>
                    <li>💬 Sharing it wif otherz who might find it useful</li>
                    <li>🐛 Reporting bugz or suggesting featurez</li>
                </ul>
            </div>
            
            <p style="text-align: center; margin-top: 2rem; color: var(--text-light);">Thank u 4 being awesome! U iz best! 🎉😻</p>
        `
    }
};

function openWizard() {
    currentWizardStep = 1;
    const modal = document.getElementById('wizardModal');
    
    // Speichere aktuelle Scroll-Position
    const scrollY = window.scrollY;
    document.body.style.top = `-${scrollY}px`;
    
    modal.classList.add('show');
    document.body.classList.add('modal-open');
    updateWizardStep();
}

function closeWizard() {
    const modal = document.getElementById('wizardModal');
    modal.classList.remove('show');
    document.body.classList.remove('modal-open');
    
    // Stelle Scroll-Position wieder her
    const scrollY = document.body.style.top;
    document.body.style.top = '';
    window.scrollTo(0, parseInt(scrollY || '0') * -1);
}

function wizardNextStep() {
    if (currentWizardStep < totalWizardSteps) {
        currentWizardStep++;
        updateWizardStep();
    }
}

function wizardPrevStep() {
    if (currentWizardStep > 1) {
        currentWizardStep--;
        updateWizardStep();
    }
}

function updateWizardStep() {
    // Update progress indicators
    const progressSteps = document.querySelectorAll('.progress-step');
    const progressLines = document.querySelectorAll('.progress-line');
    
    progressSteps.forEach((step, index) => {
        const stepNum = index + 1;
        step.classList.remove('active', 'completed');
        
        if (stepNum < currentWizardStep) {
            step.classList.add('completed');
        } else if (stepNum === currentWizardStep) {
            step.classList.add('active');
        }
    });
    
    progressLines.forEach((line, index) => {
        line.classList.remove('completed');
        if (index + 1 < currentWizardStep) {
            line.classList.add('completed');
        }
    });
    
    // Update content
    const wizardContent = document.getElementById('wizardContent');
    const stepData = wizardSteps[currentWizardStep];
    
    // Use LOLcat version if LOLcat mode is active
    const title = lolcatMode && stepData.titleLolcat ? stepData.titleLolcat : stepData.title;
    const content = lolcatMode && stepData.contentLolcat ? stepData.contentLolcat : stepData.content;
    
    document.getElementById('wizardTitle').textContent = title;
    wizardContent.innerHTML = content;
    
    // Update buttons
    const prevBtn = document.getElementById('wizardPrevBtn');
    const nextBtn = document.getElementById('wizardNextBtn');
    
    if (currentWizardStep === 1) {
        prevBtn.style.display = 'none';
    } else {
        prevBtn.style.display = 'inline-block';
    }
    
    if (currentWizardStep === totalWizardSteps) {
        nextBtn.textContent = 'Finish';
        nextBtn.onclick = closeWizard;
    } else {
        nextBtn.textContent = 'Next →';
        nextBtn.onclick = wizardNextStep;
    }
}

function copyCode(button, text) {
    navigator.clipboard.writeText(text).then(() => {
        const originalText = button.textContent;
        button.textContent = '✅ Copied!';
        button.classList.add('copied');
        
        setTimeout(() => {
            button.textContent = originalText;
            button.classList.remove('copied');
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy:', err);
        button.textContent = '❌ Failed';
        setTimeout(() => {
            button.textContent = '📋 Copy';
        }, 2000);
    });
}

async function runTestFromWizard() {
    const testBtn = document.getElementById('wizardTestBtn');
    const resultsDiv = document.getElementById('wizardTestResults');
    
    // Disable button
    testBtn.disabled = true;
    testBtn.textContent = lolcatMode ? '🔄 Testin... plz wait 😺' : '🔄 Testing...';
    
    try {
        // Use the same ports as specified in the script (80, 443)
        const ports = '80,443';
        const ipv4Host = 'ipv4-cgnat.admon.me';
        const ipv6Host = 'ipv6-cgnat.admon.me';
        
        const ipv4Url = `https://${ipv4Host}/check?ports=${ports}&tls_analyze=true`;
        const ipv6Url = `https://${ipv6Host}/check?ports=${ports}&tls_analyze=true`;
        
        // Parallel beide Requests starten
        const [ipv4Result, ipv6Result] = await Promise.allSettled([
            (async () => {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 25000);
                try {
                    const response = await fetch(ipv4Url, { signal: controller.signal });
                    clearTimeout(timeoutId);
                    return await response.json();
                } catch (e) {
                    clearTimeout(timeoutId);
                    throw e;
                }
            })(),
            (async () => {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 25000);
                try {
                    const response = await fetch(ipv6Url, { signal: controller.signal });
                    clearTimeout(timeoutId);
                    return await response.json();
                } catch (e) {
                    clearTimeout(timeoutId);
                    throw e;
                }
            })()
        ]);
        
        // Ergebnisse auswerten
        let ipv4Data = null;
        let ipv6Data = null;
        
        const grouped = splitResultsByIPVersion(
            ipv4Result.status === 'fulfilled' ? ipv4Result.value : null,
            ipv6Result.status === 'fulfilled' ? ipv6Result.value : null
        );
        ipv4Data = grouped.ipv4Data;
        ipv6Data = grouped.ipv6Data;
        
        // Wenn beide fehlschlagen, Fehler werfen
        if (!ipv4Data && !ipv6Data) {
            throw new Error(lolcatMode ? 'Both IPv4 and IPv6 checks faild 😿' : 'Both IPv4 and IPv6 checks failed');
        }
        
        // Display results
        let resultsHtml = '<div class="wizard-test-results">';
        
        // IPv4 Results
        if (ipv4Data) {
            resultsHtml += `<h4 style="color: var(--primary); margin-top: 1.5rem;">🌐 IPv4 Results</h4>`;
            resultsHtml += `<p><strong>${lolcatMode ? 'Ur Public IPv4:' : 'Your Public IPv4:'}</strong> ${ipv4Data.client_ip}</p>`;
            resultsHtml += '<div style="margin-top: 1rem;">';
            
            Object.keys(ipv4Data.results).forEach(port => {
                const result = ipv4Data.results[port];
                const statusClass = result.reachable ? 'success-box' : 'warning-box';
                const statusIcon = result.reachable ? '✅' : '❌';
                const statusText = lolcatMode 
                    ? (result.reachable ? 'Reachable! Yay!' : 'Unreachable 😿') 
                    : (result.reachable ? 'Reachable' : 'Unreachable');
                
                resultsHtml += `
                    <div class="${statusClass}" style="margin-bottom: 1rem;">
                        <p><strong>${statusIcon} Port ${port}:</strong> ${statusText}</p>
                    </div>
                `;
            });
            
            resultsHtml += '</div>';
        } else {
            resultsHtml += `<h4 style="color: var(--primary); margin-top: 1.5rem;">🌐 IPv4 Results</h4>`;
            resultsHtml += `<div class="warning-box"><p><strong>❌ IPv4 check failed</strong></p></div>`;
        }
        
        // IPv6 Results
        if (ipv6Data) {
            resultsHtml += `<h4 style="color: var(--primary); margin-top: 1.5rem;">🌐 IPv6 Results</h4>`;
            resultsHtml += `<p><strong>${lolcatMode ? 'Ur Public IPv6:' : 'Your Public IPv6:'}</strong> ${ipv6Data.client_ip}</p>`;
            resultsHtml += '<div style="margin-top: 1rem;">';
            
            Object.keys(ipv6Data.results).forEach(port => {
                const result = ipv6Data.results[port];
                const statusClass = result.reachable ? 'success-box' : 'warning-box';
                const statusIcon = result.reachable ? '✅' : '❌';
                const statusText = lolcatMode 
                    ? (result.reachable ? 'Reachable! Yay!' : 'Unreachable 😿') 
                    : (result.reachable ? 'Reachable' : 'Unreachable');
                
                resultsHtml += `
                    <div class="${statusClass}" style="margin-bottom: 1rem;">
                        <p><strong>${statusIcon} Port ${port}:</strong> ${statusText}</p>
                    </div>
                `;
            });
            
            resultsHtml += '</div>';
        } else {
            resultsHtml += `<h4 style="color: var(--primary); margin-top: 1.5rem;">🌐 IPv6 Results</h4>`;
            resultsHtml += `<div class="warning-box"><p><strong>❌ IPv6 check failed</strong></p></div>`;
        }
        
        resultsHtml += '</div>';
        resultsDiv.innerHTML = resultsHtml;
        
        // Re-enable button
        testBtn.disabled = false;
        testBtn.textContent = lolcatMode ? '🔍 Run Test Again plz' : '🔍 Run Test Again';
        
    } catch (err) {
        let errorMessage = err.message;
        
        // Handle timeout errors
        if (err.name === 'AbortError') {
            errorMessage = lolcatMode 
                ? "Request timeout! Server took 2 long 2 respond. 😿" 
                : "Request timeout! Server took too long to respond.";
        }
        
        resultsDiv.innerHTML = `
            <div class="warning-box">
                <p><strong>❌ ${lolcatMode ? 'Test Faild:' : 'Test Failed:'}</strong> ${errorMessage}</p>
                <p>${lolcatMode ? 'Make sure u haz run teh firewall script on ur router first plz.' : 'Make sure you have run the firewall script on your router first.'}</p>
            </div>
        `;
        
        testBtn.disabled = false;
        testBtn.textContent = lolcatMode ? '🔍 Try Again plz' : '🔍 Try Again';
    }
}

// Close modal when clicking outside
window.onclick = function(event) {
    const wizardModal = document.getElementById('wizardModal');
    const routerTestModal = document.getElementById('routerTestModal');
    if (event.target === wizardModal) {
        closeWizard();
    }
    if (event.target === routerTestModal) {
        closeRouterTestModal();
    }
}

// Close modal on Escape key
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        closeWizard();
        closeRouterTestModal();
    }
});

// ============================================================================
// Direct Router Test Modal
// ============================================================================

const routerTestContent = {
    normal: {
        title: '🚀 Test Directly on Your Router',
        infoBox: '<strong>💡 For Experts:</strong> This command runs the test directly on your router via SSH, without needing this website.',
        instruction: '<strong>Simply copy and run this command on your GL.iNet router:</strong>',
        copyBtn: '📋 Copy',
        advantagesTitle: '<strong>✨ Advantages:</strong>',
        advantages: [
            '✅ Works even when connected via VPN',
            '✅ Automatically handles firewall configuration',
            '✅ Tests both IPv4 and IPv6 connectivity',
            '✅ Shows results directly in your terminal',
            '✅ No manual intervention needed'
        ],
        advancedTitle: '🔧 Advanced Options (Click to expand)',
        testPortsLabel: '<strong>Test specific ports:</strong>',
        manualModeLabel: '<strong>Manual mode (for web testing):</strong>',
        helpLabel: '<strong>View help and all options:</strong>',
        closeBtn: 'Close'
    },
    lolcat: {
        title: '🚀 Test Directly on Ur Router',
        infoBox: '<strong>💡 4 Expertz:</strong> Dis command runz teh test directly on ur router via SSH, without needin dis website. So pro! 😺',
        instruction: '<strong>Simply copy and run dis command on ur GL.iNet router plz:</strong>',
        copyBtn: '📋 Copy dis',
        advantagesTitle: '<strong>✨ Advantagez (much wow!):</strong>',
        advantages: [
            '✅ Werkz even wen connected via VPN (no problemo!)',
            '✅ Automatically handlez firewall configuration (so smart!)',
            '✅ Tests both IPv4 and IPv6 connectivity (all teh IPs!)',
            '✅ Showz results directly in ur terminal (instant!)',
            '✅ No manual intervention needed (lazy approved! 😸)'
        ],
        advancedTitle: '🔧 Advanced Optionz 4 power userz (Click 2 expand)',
        testPortsLabel: '<strong>Test specific ports plz:</strong>',
        manualModeLabel: '<strong>Manual mode (4 web testin):</strong>',
        helpLabel: '<strong>View halp and all optionz:</strong>',
        closeBtn: 'Close dis'
    }
};

function openRouterTestModal() {
    const modal = document.getElementById('routerTestModal');
    const content = lolcatMode ? routerTestContent.lolcat : routerTestContent.normal;
    
    // Update modal content
    const modalHeader = modal.querySelector('.modal-header h2');
    const infoBox = modal.querySelector('.info-box p');
    const instruction = modal.querySelector('.modal-body > p');
    const advantagesBox = modal.querySelector('.success-box');
    const advancedSummary = modal.querySelector('details summary');
    const advancedLabels = modal.querySelectorAll('details > div > p');
    const closeButton = modal.querySelector('.modal-footer button');
    const copyButtons = modal.querySelectorAll('.copy-btn');
    
    // Set content
    modalHeader.innerHTML = content.title;
    infoBox.innerHTML = content.infoBox;
    instruction.innerHTML = content.instruction;
    advancedSummary.innerHTML = content.advancedTitle;
    closeButton.textContent = content.closeBtn;
    
    // Update copy buttons
    copyButtons.forEach(btn => {
        btn.innerHTML = content.copyBtn;
    });
    
    // Update advantages
    let advantagesHtml = content.advantagesTitle + '<ul>';
    content.advantages.forEach(adv => {
        advantagesHtml += `<li>${adv}</li>`;
    });
    advantagesHtml += '</ul>';
    advantagesBox.innerHTML = advantagesHtml;
    
    // Update advanced option labels
    if (advancedLabels.length >= 3) {
        advancedLabels[0].innerHTML = content.testPortsLabel;
        advancedLabels[1].innerHTML = content.manualModeLabel;
        advancedLabels[2].innerHTML = content.helpLabel;
    }
    
    modal.style.display = 'block';
    // Prevent body scrolling when modal is open
    document.body.style.overflow = 'hidden';
}

function closeRouterTestModal() {
    const modal = document.getElementById('routerTestModal');
    modal.style.display = 'none';
    // Restore body scrolling
    document.body.style.overflow = 'auto';
}
