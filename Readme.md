# 0xD4rKEYe Domain Enumeration Tool

**Version:** 1.0  
**Status:** Beta

## Overview

The **0xD4rKEYe Domain Enumeration Tool** is a powerful and comprehensive domain information gathering tool. It is designed to retrieve and present detailed information about domains, including DNS records, WHOIS data, SSL/TLS certificate details, web server information, and more. This tool is particularly useful for penetration testers, security researchers, and anyone interested in understanding the structure and security of a domain.

## Features

- **IP Address Resolution:** Retrieves the IP address of the domain and performs reverse DNS lookups.
- **WHOIS Information:** Fetches and displays detailed WHOIS data for the domain.
- **DNS Records:** Collects various DNS records (A, AAAA, MX, NS, TXT, CNAME, SRV, PTR).
- **Shared DNS Servers:** Identifies shared DNS servers for the domain.
- **Web Server Information:** Retrieves the web server information by analyzing HTTP headers.
- **DNSSEC Validation:** Checks if DNSSEC is enabled for the domain.
- **SSL/TLS Certificate Info:** Extracts and presents SSL/TLS certificate details.
- **Nmap Scanning:** Performs an Nmap scan to gather information about open ports and services.
- **DNS Host Records:** Finds DNS host records (subdomains) associated with the domain.
- **IP Geolocation:** Provides geolocation information for the domain's IP address.

## Usage

To use the tool, simply run the following command in your terminal:

```bash
python 0xD4rKEYe.py [domain]
```

### Example:

```bash
python 0xD4rKEYe.py example.com
```

You can also specify a configuration file if needed:

```bash
python 0xD4rKEYe.py example.com -c config.json
```

## Installation

1. Clone the repository:

```bash
git clone https://github.com/0xD4rKEYe/0xD4rKEYe.git

2. Change to the tool's directory:

```bash
cd 0xD4rKEYe
```

3. Install the required dependencies:

```bash
pip install -r requirements.txt
```

4. Run the tool:

```bash
python 0xD4rKEYe.py [domain]
```

## Disclaimer

**0xD4rKEYe** is currently in beta. While it has been tested and works as intended, there may be minor issues or inaccuracies in the results. Please cross-verify any critical findings with other tools or online resources.
