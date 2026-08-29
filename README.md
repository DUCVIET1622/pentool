# Pentool

> A lightweight, multi-purpose reconnaissance toolkit for authorized penetration testing — built in pure Python with zero external dependencies.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey)
![Dependencies](https://img.shields.io/badge/dependencies-none-success)

## Features

| Module | Description | Technique Mapping |
|--------|-------------|-------------------|
| `scan` | Multithreaded TCP port scanner with configurable timeout | Network Discovery (T1046) |
| `banner` | Service banner grabbing for fingerprinting | Service Discovery |
| `dirs` | Async directory/file brute-forcing against web servers | Content Discovery |
| `sub` | Subdomain enumeration via DNS resolution | Subdomain Discovery (T1018) |

**Why Pentool?**
- **Zero dependencies** — pure standard library, runs anywhere Python runs
- **Fast** — thread-pool based concurrent scanning
- **Portable** — single file, no installation required
- **Beginner-friendly** — clean, commented source code for learning how recon tools work internally

## Quick Start

### Prerequisites

- Python 3.8 or newer ([python.org/downloads](https://www.python.org/downloads/))

### Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/pentool.git
cd pentool

# Run directly — no dependencies to install
python pentool.py --help
```

### Windows (CMD)

```cmd
git clone https://github.com/<your-username>/pentool.git
cd pentool
python pentool.py scan 127.0.0.1 -p 1-1000
```

## Usage

```text
pentool.py <module> <target> [options]
```

### Port Scanning

```bash
# Scan a host on a port range
python pentool.py scan 192.168.1.10 -p 1-1000

# Quick check on common ports
python pentool.py scan 192.168.1.10 -p 22,80,443,3389,8080
```

### Banner Grabbing

```bash
# Fingerprint services on open ports
python pentool.py banner 192.168.1.10 -p 21,22,80,443
```

### Directory Brute-forcing

```bash
# Requires a wordlist file
python pentool.py dirs http://192.168.1.50 -w wordlists/common.txt
```

Recommended wordlists:
- [dirb common.txt](https://github.com/vbhavank/Unstructured/blob/master/common.txt)
- [SecLists](https://github.com/danielmiessler/SecLists)

### Subdomain Enumeration

```bash
python pentool.py sub example-lab.local -w wordlists/subdomains.txt
```

## Example Output

```
$ python pentool.py scan 192.168.1.10 -p 1-100

[*] Scanning 192.168.1.10 (100 ports, 200 threads)
[+] 22/tcp    open
[+] 80/tcp    open
[+] 443/tcp   open

[*] Scan complete: 3 ports open in 1.42s
```

## Project Structure

```
pentool/
├── pentool.py          # Main toolkit (single-file design)
├── wordlists/
│   └── common.txt      # Sample wordlist for dirs/sub modules
├── README.md
└── LICENSE
```

## Roadmap

- [ ] SYN scanning via Scapy (stealth mode)
- [ ] JSON/HTML report export
- [ ] Web technology fingerprinting (Wappalyzer-style)
- [ ] Basic SQLi / command injection probes for lab targets
- [ ] Config file support (`pentool.yaml`)

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/amazing-module`)
3. Commit changes (`git commit -m 'Add amazing module'`)
4. Push (`git push origin feature/amazing-module`)
5. Open a Pull Request

## Legal Disclaimer

This tool is provided for **educational purposes and authorized security testing only**. You are responsible for obtaining proper authorization before scanning any system. Unauthorized access to computer systems is illegal in most jurisdictions (e.g., Computer Fraud and Abuse Act, EU Directive 2013/40, Vietnamese Penal Code Article 288).

## License

Distributed under the MIT License. See `LICENSE` for details.

## Acknowledgments

- Inspired by classic recon tools: nmap, dirb, gobuster
- Built for cybersecurity students and aspiring pentesters

owner: DUCVIET1622
