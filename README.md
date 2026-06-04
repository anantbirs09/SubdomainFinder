
# ABS Scan ▲

**Enterprise-grade Subdomain Intelligence & Verification Engine**

ABS Scan is a fast, real-time desktop application built with Electron and Node.js. It takes a target domain and discovers subdomains across multiple intelligence sources, verifies their DNS resolution, checks for active web servers, and instantly highlights high-value targets.

## ✨ Features

- **Multi-Source Discovery:** Pulls subdomain data from `crt.sh`, `AlienVault OTX`, `HackerTarget`, and performs local DNS brute-forcing.
- **Real-Time Data Streaming:** Uses Server-Sent Events (SSE) to stream results directly to the beautiful GUI as soon as they are discovered.
- **High-Value Target Highlighting:** Automatically flags critical endpoints (e.g., domains containing `api`, `admin`, `dev`, `vpn`, `stage`) with a glowing amber badge.
- **Live Verification:** Checks if the discovered subdomains have active IP mappings and whether they are responding to HTTP/HTTPS requests.
- **Data Export:** Export your results seamlessly to `CSV` or `JSON` for further security auditing.
- **Programmatic API:** Run scans headless and consume the JSON stream directly via curl.

## 🚀 Quick Start

### Prerequisites
Make sure you have [Node.js](https://nodejs.org/) installed on your machine.

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/anantbirs09/SubdomainFinder.git
   cd SubdomainFinder
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

### Running the Application

To launch the beautiful Electron Desktop GUI, run:
```bash
npm run electron:start
```

To run only the backend server (accessible via web browser at `http://localhost:3000`), run:
```bash
npm start
```

## 📂 Project Structure

- **`main.js`**: The Electron bootstrap file. It initializes the desktop window and spawns the Express backend as a background process.
- **`server.js`**: The Express.js backend. Handles the `/api/scan` endpoint, fetches data from third-party APIs, runs the DNS brute-forcer, and manages the Server-Sent Events (SSE) stream.
- **`public/index.html`**: The main UI layout, featuring a glassmorphism design and animated gradient mesh background.
- **`public/style.css`**: All the CSS tokens, animations, and custom styling that gives ABS Scan its premium look.
- **`public/app.js`**: Client-side logic for connecting to the SSE stream, dynamically updating statistics, managing the search/filter systems, and handling CSV/JSON exports.
- **`subdomains.txt`**: A wordlist file used by the backend for DNS brute-forcing common subdomains.

## 📡 API Usage

You can bypass the GUI entirely and integrate ABS Scan into your own automated workflows.

```bash
curl -N "http://localhost:3000/api/scan?domain=example.com"
```
*The `-N` flag ensures curl streams the JSON data in real-time as it arrives.*

## ⚠️ Disclaimer
ABS Scan is made for authorized security audits, bug bounties, and network mapping. Please use responsibly and ensure you have permission to scan the target domains.
```
