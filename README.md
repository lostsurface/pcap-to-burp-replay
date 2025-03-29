# pcap-to-burp-replay

**Part of the [OpenBash](https://www.openbash.com) project — making pentesters' daily work easier.**

This is a command-line tool that extracts HTTP traffic from `.pcap` files and replays the HTTP requests through Burp Suite using its proxy listener. It helps security analysts and pentesters to reconstruct and analyze HTTP request flows from captured network traffic, simulating both `http://` and `https://` schemes for extended coverage.

---

## 🧰 Features

- Extracts HTTP requests from `.pcap` files using `tcpflow`.
- Parses and rebuilds valid HTTP requests.
- Sends each request via `http://` and `https://` to maximize endpoint coverage.
- Routes all requests through the Burp Suite proxy for full interception and analysis.
- Robust error handling and formatting checks.
- Ideal for traffic replay, forensic analysis, or passive discovery in offensive security.

---

## ⚙️ Requirements

- Python 3.x
- `tcpflow` (for HTTP stream extraction)

### 📦 Installation (macOS with Homebrew):

```bash
brew install tcpflow
pip3 install requests
```

---

## 🚀 Usage

1. Start Burp Suite and activate the proxy listener at `127.0.0.1:8080`. Set "Intercept" to OFF.

2. Run the tool:

```bash
python3 pcap_to_burp_replay.py path/to/capture.pcap
```

3. The HTTP requests will appear in **Burp → Proxy → HTTP history**, duplicated for both `http` and `https`.

---

## 🔒 HTTPS Note

If your `.pcap` file contains HTTPS traffic, it cannot be reconstructed directly unless decrypted. This tool attempts to reach both `http` and `https` variants of each request, even if the original capture was in plaintext only.

---

## 📜 License

MIT License – see [LICENSE](LICENSE) for details.

---

## 🤝 Contributions

Pull requests and improvements are welcome.

---
**Built with ❤️ by [OpenBash](https://www.openbash.com)** — because pentesters deserve better tools.
