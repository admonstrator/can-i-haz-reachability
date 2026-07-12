<div align="center">

<h1>🐱 Can I Haz Reachability? 📡</h1>

**A professional tool to verify network reachability, TLS configurations, and firewall settings.**

[![License](https://img.shields.io/github/license/Admonstrator/can-i-haz-reachability?style=for-the-badge)](LICENSE) [![Stars](https://img.shields.io/badge/stars-4-orange?style=for-the-badge&logo=github)](https://github.com/Admonstrator/can-i-haz-reachability/stargazers)

> 😺 **O HAI!** I can haz reachability? I checkz if ur ports are open so u don't haz to guess. It's like ping but fancy. Kthxbye!

<div align="center">

👉 Check it out here: [https://cgnat.admon.me](https://cgnat.admon.me) 👈

</div>

---

## 💖 Support the Project

If you find this tool helpful, consider supporting its development:

[![GitHub Sponsors](https://img.shields.io/badge/GitHub-Sponsors-EA4AAA?style=for-the-badge&logo=github)](https://github.com/sponsors/admonstrator) [![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/admon) [![Ko-fi](https://img.shields.io/badge/Ko--fi-FF5E5B?style=for-the-badge&logo=ko-fi&logoColor=white)](https://ko-fi.com/admon) [![PayPal](https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://paypal.me/aaronviehl)

</div>

---

## 📖 About

**Can I Haz Reachability?** (also known as the Reflector Server) is a robust Go-based service designed to verify if specific ports on a client's IP address are reachable from the internet. It acts as an external "mirror," attempting to connect back to the requestor to validate port forwarding, detect Carrier-Grade NAT (CGNAT), and analyze firewall configurations.

Beyond simple connectivity, it offers advanced features like TLS certificate analysis and service banner grabbing, making it an essential tool for network troubleshooting and verification.

---

## ✨ Features

- 🚀 **Port Reachability Check** – Verifies TCP connectivity to specified ports on the requestor's public IP.
- 🔒 **TLS/SSL Analysis** – Performs a detailed inspection of SSL certificates on port 443 (validity, chain, cipher suites).
- 🕵️ **Banner Grabbing** – Identifies running services (e.g., SSH versions) by retrieving their initial connection banner.
- 🛡️ **Reflector Challenge** – Supports a token-based challenge system to verify ownership of the target server.
- 🛑 **Rate Limiting** – Includes built-in, IP-based rate limiting to prevent abuse.
- 🙈 **Privacy Focused** – Logs are strictly anonymized. Private/internal IP ranges are blocked by default.

---

## 📋 Requirements

| Requirement          | Details                                       |
| -------------------- | --------------------------------------------- |
| **Container Engine** | Docker or Podman (recommended for deployment) |
| **Language**         | Go 1.25+ (if building from source)            |
| **Architecture**     | x86_64, arm64 (multi-arch support via Docker) |

---

## 🚀 Quick Start

### Using Docker

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

| Architecture | Description |
| --- | --- |
| `linux/amd64` | x86-64 (Intel/AMD) |
| `linux/arm64` | ARM 64-bit (Raspberry Pi 4/5, Apple Silicon, etc.) |

### Using Docker Compose

1. Navigate to the deployment directory:
   ```bash
   cd deploy/docker
   ```

2. Start the service:
   ```bash
   docker-compose up -d --build
   ```

### Using Podman (Quadlet)

1. Build the image:
   ```bash
   podman build -t reflector-server -f deploy/docker/Dockerfile .
   ```

2. Copy the `.container` file and create the environment file:
   ```bash
   mkdir -p ~/.config/containers/systemd/
   cp deploy/podman/reflector.container ~/.config/containers/systemd/
   cp env.example ~/.config/containers/systemd/reflector.env
   ```

3. (Optional) Edit the environment file to customize settings:
   ```bash
   nano ~/.config/containers/systemd/reflector.env
   ```

4. Reload and start the service:
   ```bash
   systemctl --user daemon-reload
   systemctl --user start reflector
   ```

---

## 🎛️ Configuration

The service is configured using environment variables. These can be set in `docker-compose.yml` or a `.env` file.

| Variable                       | Description                                         | Default            |
| ------------------------------ | --------------------------------------------------- | ------------------ |
| `REFLECTOR_PORT`               | The TCP port the server listens on.                 | `8080`             |
| `REFLECTOR_TIMEOUT`            | Connection timeout for reachability checks.         | `5s`               |
| `REFLECTOR_ALLOWED_PORTS`      | Comma-separated list of ports allowed to be tested. | `80,443,8080,8443` |
| `REFLECTOR_RATE_LIMIT_PER_MIN` | Maximum number of requests per IP per minute.       | `10`               |
| `REFLECTOR_LOG_DIR`            | Directory where application logs are stored.        | `/logs`            |

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

**Example:**
```bash
curl "http://localhost:8080/check?ports=80,443&tls_analyze=true"
```

### Simple Check (`GET /simple`)
Returns a concise "yes" or "no" string, ideal for automated scripts.

**Query Parameters:**
- `port`: The single port to check (default: 80).

**Example:**
```bash
curl "http://localhost:8080/simple?port=443"
# Output: yes
```

### Health Check (`GET /health`)
Returns the service status and basic runtime statistics.

---

## 🔍 Key Features Explained

### Privacy & Security
This service is designed with privacy in mind. Access logs automatically anonymize client IP addresses (e.g., masking the last octet) to ensure user privacy while allowing for basic diagnostics. Additionally, the service refuses to scan private or internal IP ranges (RFC 1918) to prevent misuse as an internal network scanner.

---

## 💡 Getting Help

Need assistance or have questions?

- 💬 [Join the discussion on GL.iNet Forum](https://forum.gl-inet.com/t/how-to-update-tailscale-on-arm64/37582) – Community support
- 💬 [Join GL.iNet Discord](https://link.gl-inet.com/website-discord-support) – Real-time chat
- 🐛 [Report issues on GitHub](https://github.com/Admonstrator/can-i-haz-reachability/issues) – Bug reports and feature requests
- 📧 Contact via forum private message – For private inquiries

---

## ⚠️ Disclaimer

This script is provided **as-is** without any warranty. Use it at your own risk.

It may potentially:

- 🔥 Break your router, computer, or network
- 🔥 Cause unexpected system behavior
- 🔥 Even burn down your house (okay, probably not, but you get the idea)

**You have been warned!**

Always read the documentation carefully and understand what a script does before running it.

---

## 📜 License

This project is licensed under the **MIT License** – see the [LICENSE](https://github.com/Admonstrator/can-i-haz-reachability/blob/main/LICENSE) file for details.

---

<div align="center">

## 🧰 Part of the GL.iNet Toolbox

This project is part of a comprehensive collection of tools for GL.iNet routers.

**Explore more tools and utilities:**

[![GL.iNet Toolbox](https://img.shields.io/badge/🧰_GL.iNet_Toolbox-Explore_All_Tools-blue?style=for-the-badge)](https://github.com/Admonstrator/glinet-toolbox)

*Discover AdGuard Home Updater, ACME Certificate Manager, and more community-driven projects!*

</div>

---

<div align="center">

**Made with ❤️ by [Admon](https://github.com/Admonstrator) for the GL.iNet Community**

⭐ If you find this useful, please star the repository!

</div>

<div align="center">

_Last updated: 2026-07-12_

</div>
