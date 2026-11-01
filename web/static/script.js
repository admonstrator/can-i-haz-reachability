/**
 * ============================================================================
 * Can I Haz Reachability? - Client-Side Application
 * ============================================================================
 * 
 * @description  Web interface for guiding users through router-side reachability tests.
 * 
 * @author       Admon
 * @repository   admonstrator/can-i-haz-reachability
 * @license      See LICENSE file in repository root
 * 
 * Features:
 * - Router-side IPv4 and IPv6 reachability tests
 * - LOLcat mode for fun 🐱
 * - Step-by-step wizard for troubleshooting
 * 
 * ============================================================================
 */

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
            '.router-test-intro .options-label': 'Router-side reachability test',
            '.router-test-btn .btn-text': '🚀 Start Router Test plz',
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
            
            <p><strong>How it works:</strong></p>
            <ol>
                <li>You'll connect to your router via SSH</li>
                <li>Run a test script that temporarily opens the firewall</li>
                <li>Run the automatic reachability test from the router</li>
                <li>The script automatically closes any temporary firewall rules</li>
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
            
            <p><strong>How dis werkz:</strong></p>
            <ol>
                <li>U'll connect 2 ur router via SSH (so pro!)</li>
                <li>Run test script dat temporarily openz teh firewall</li>
                <li>Run teh automatic reachability test from teh router</li>
                <li>Teh script automatically closez any temporary firewall rulez</li>
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
            <p>Run the automatic test directly from your router.</p>
            
            <h4 style="color: var(--primary); margin-top: 1.5rem;">Automatic Router Test</h4>
            <p>The script will automatically open the firewall, test it, and close it again - all in one command!</p>
            
            <div class="code-block">
                <button class="copy-btn" onclick="copyCode(this, 'curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --auto-test')">📋 Copy</button>
                <code>curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --auto-test</code>
            </div>
            
            <div class="success-box">
                <p><strong>✨ This is the easiest way!</strong> The script will show you the results directly in your terminal and automatically clean up afterwards.</p>
            </div>
            
            <p style="margin-top: 1rem;"><strong>What the script does:</strong></p>
            <ul>
                <li>Checks your current firewall configuration</li>
                <li>Temporarily opens ports 80 and 443 for testing</li>
                <li>Tests IPv4 and IPv6 directly from the router and shows results in the terminal</li>
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
            <p>Run teh automatic test directly from ur router.</p>
            
            <h4 style="color: var(--primary); margin-top: 1.5rem;">Automatic Router Test (4 lazy catz 😺)</h4>
            <p>Teh script will automatically open teh firewall, test it, and close it again - all in 1 command! So ez!</p>
            
            <div class="code-block">
                <button class="copy-btn" onclick="copyCode(this, 'curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --auto-test')">📋 Copy dis magik</button>
                <code>curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --auto-test</code>
            </div>
            
            <div class="success-box">
                <p><strong>✨ Dis iz teh easiest way!</strong> Teh script will show u teh results directly in ur terminal and automatically clean up afterwards. No manual werk! Purrfect! 🐱</p>
            </div>
            
            <p style="margin-top: 1rem;"><strong>Wut teh script doez:</strong></p>
            <ul>
                <li>Checks ur current firewall configuration (safe!)</li>
                <li>Temporarily openz ports 80 and 443 4 testin</li>
                <li>Tests IPv4 and IPv6 directly from teh router and showz results in teh terminal</li>
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
                    
                    <p><strong>Cleanup only:</strong></p>
                    <div class="code-block">
                        <button class="copy-btn" onclick="copyCode(this, 'curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --cleanup')">📋 Copy dis</button>
                        <code>curl -sSL https://cgnat.admon.me/test.sh | sh -s -- --cleanup</code>
                    </div>
                </div>
            </details>
            
            <p style="margin-top: 1.5rem;">Aftr runnin teh command, u'll see teh firewall status and IPv4/IPv6 test results in ur terminal. Much info! 😸</p>
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
            
        `,
        contentLolcat: `
            <h3>✅ Test Results & Next Stepz</h3>
            
            <div class="info-box">
                <p><strong>If u usd --auto-test:</strong></p>
                <p>U should already see teh test results in ur SSH terminal! Teh firewall has been automatically closd. Much convenient! 😺</p>
            </div>
            
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
    if (advancedLabels.length >= 2) {
        advancedLabels[0].innerHTML = content.testPortsLabel;
        advancedLabels[1].innerHTML = content.helpLabel;
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
