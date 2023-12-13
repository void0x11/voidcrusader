# Network Reconnaissance and Security Analysis Tool

![image](https://github.com/void0x11/voidcrusader/assets/69634124/10f7e96d-47f3-4a50-9932-846d25de1f61)


## Introduction
This comprehensive suite of tools is designed for network reconnaissance and security analysis. It's intended for network administrators, security professionals, and cybersecurity enthusiasts, providing functionalities like network scanning, DNS analysis, SSL/TLS verification, and more. This toolset is crucial for network security assessments, reconnaissance, and educational purposes.

## Features
- **Network Scanning**: Utilizes `nmap` for various scans.
- **DNS Enumeration**: Retrieves DNS records for a domain.
- **SSL/TLS Scanning**: Verifies SSL/TLS support on servers.
- **WHOIS Lookup**: Gathers domain registration details.
- **DNSSEC Checking**: Assesses DNSSEC implementation on domains.
- **Email Address Enumeration**: Validates and analyzes email addresses.
- **Subdomain Enumeration**: Discovers subdomains of a given domain.
- **Honeypot Detection**: Identifies potential honeypots.

## System Requirements
- Python 3.6 or later.
- `nmap` installed on the system (for network scanning features).
- Network access for performing scans and queries.
- Compatible with Linux, macOS, and Windows systems.

## Installation
1. Clone the repository:
2. Install Python dependencies


## Modules
### `ssl_scanner.py`
Scans hosts for SSL/TLS support.

### `whois_lookup.py`
Performs WHOIS lookups for domains.

### `dns_enumeration.py`
Enumerates DNS records.

### `subdomain_enumeration.py`
Discovers and lists subdomains.

### `email_address_enumeration.py`
Checks and enumerates email addresses.

### `honeypot_detector.py`
Detects potential honeypots by analyzing network responses.

### `network_scanner.py`
Conducts various network scans using `nmap`.

### `dnssec_checker.py`
Verifies DNSSEC implementation on domains.

## Usage
Run the application:
```
python main.py

```

Follow the on-screen menu to select the desired functionality. Each option corresponds to a specific module and its capabilities.

## Contributing
Contributions are welcome. Please adhere to standard fork, branch, and pull request workflows.

## License
Distributed under the [MIT License](LICENSE).

## Disclaimer
This tool is for educational and ethical testing purposes only. The author is not responsible for misuse or damage caused by this tool.

## Contact
For queries or feedback, contact [Your Email](mailto:youremail@example.com).
