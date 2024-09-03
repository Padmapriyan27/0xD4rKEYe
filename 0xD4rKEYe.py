import subprocess
import socket
import dns.resolver
import requests
import ssl
import json
from datetime import datetime
from pyfiglet import figlet_format
import logging
import argparse
from tabulate import tabulate

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ANSI escape sequences for colors
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[39m'

def print_banner():
    """Print the banner of the tool."""
    banner = figlet_format("0xD4rKEYe", font='slant')
    print(Colors.OKGREEN + banner + Colors.ENDC)

def get_ip_info(domain):
    """Get IP information for the domain."""
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        logging.error("Could not resolve IP address.")
        return None

def get_whois_info(domain):
    """Get detailed WHOIS information for the domain."""
    try:
        whois_command = f"whois {domain}"
        whois_output = subprocess.check_output(whois_command, shell=True, universal_newlines=True)
        return whois_output
    except subprocess.CalledProcessError as e:
        logging.error(f"Error retrieving WHOIS information: {str(e)}")
        return "Error retrieving WHOIS information."

def get_dns_records(domain):
    """Get DNS records for the domain."""
    dns_info = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SRV', 'PTR']
    
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            dns_info[record] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            dns_info[record] = "No Record Found"
    
    return dns_info

def find_shared_dns_servers(domain):
    """Find shared DNS servers for the domain."""
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        shared_dns_servers = {str(record) for record in ns_records}
        return shared_dns_servers if shared_dns_servers else "No Shared DNS Servers Found"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "No NS Records Found"

def run_nmap(domain):
    """Run Nmap on the domain and return results."""
    try:
        nmap_command = f"nmap -sV -A {domain}"  # -sV for version detection, -A for OS detection and more
        nmap_result = subprocess.check_output(nmap_command, shell=True, universal_newlines=True)
        return nmap_result
    except Exception as e:
        logging.error(f"Error running Nmap: {str(e)}")
        return "Error running Nmap."

def get_http_headers(domain):
    """Get HTTP headers for the domain."""
    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=5)
        return response.headers
    except requests.RequestException as e:
        logging.error(f"Error retrieving HTTP headers: {str(e)}")
        return f"Error retrieving HTTP headers."

def get_web_server_info(domain):
    """Identify the web server information."""
    headers = get_http_headers(domain)
    
    if isinstance(headers, dict):  # Check if headers is a dictionary
        server_info = headers.get('Server', 'Unknown')
    else:
        server_info = headers  # Use the error message if it's not a dictionary

    return str(server_info)  # Convert server_info to string

def validate_dnssec(domain):
    """Check if DNSSEC is enabled for the domain."""
    try:
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        return "DNSSEC is enabled" if answers else "DNSSEC is not enabled"
    except Exception:
        return "DNSSEC validation failed"

def get_ssl_certificate_info(domain):
    """Retrieve SSL/TLS certificate information."""
    port = 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cert_info = {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'notBefore': cert['notBefore'],
                    'notAfter': cert['notAfter'],
                }
                cert_info['notBefore'] = datetime.strptime(cert_info['notBefore'], '%b %d %H:%M:%S %Y %Z')
                cert_info['notAfter'] = datetime.strptime(cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return cert_info
    except Exception as e:
        logging.error(f"Error retrieving SSL certificate: {str(e)}")
        return f"Error retrieving SSL certificate."

def find_dns_host_records(domain):
    """Find DNS host records (subdomains) for the domain."""
    dns_info = {}
    try:
        answers = dns.resolver.resolve(domain, 'A')  # Get A records for the domain
        dns_info['A'] = [str(rdata) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        dns_info['A'] = "No A Records Found"
    
    try:
        answers = dns.resolver.resolve(domain, 'MX')  # Get MX records for the domain
        dns_info['MX'] = [str(rdata) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        dns_info['MX'] = "No MX Records Found"

    return dns_info

def reverse_dns_lookup(ip):
    """Perform a reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return "No hostname found for this IP."

def get_ip_geolocation(ip):
    """Get geolocation information for the IP address."""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        return response.json() if response.status_code == 200 else None
    except requests.RequestException as e:
        logging.error(f"Error retrieving geolocation: {str(e)}")
        return f"Error retrieving geolocation."

def save_to_json(data, filename):
    """Save data to a JSON file."""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
    logging.info(f"Data saved to {filename}")

def load_config(config_file):
    """Load configuration from a JSON file."""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.warning(f"Configuration file {config_file} not found. Using default settings.")
        return {}

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Domain Enumeration Tool")
    parser.add_argument("domain", help="Domain to enumerate information about")
    parser.add_argument("-c", "--config", help="Path to configuration file", default="config.json")
    return parser.parse_args()

def main():
    """Main function to run the domain enumeration tool."""
    print_banner()
    author = "0xD4rKEYe"
    print(Colors.HEADER + "\t\t\t\t\t","- ",author)
    key_note = ("\nDescription: The Domain Enumeration Tool is a powerful utility designed for gathering extensive information about a given domain.\n" 
                "\tWith features such as DNS record retrieval, WHOIS lookups, SSL certificate analysis, and Nmap scanning, this tool aims to provide a comprehensive overview of the domain's network presence\n"
                "\nNote: This tool is currently in beta version. While we strive for accuracy, it may occasionally produce minor discrepancies or errors in the results.\n"
                "\tWe recommend cross-verifying the information with trusted internet sources to ensure reliability.\n")

    print(Colors.OKCYAN + key_note + Colors.RESET + Colors.OKGREEN)
    args = parse_arguments()
    domain = args.domain

    # Load configuration
    config = load_config(args.config)

    # Get IP Info
    ip_info = get_ip_info(domain)
    if ip_info:
        print(Colors.OKCYAN + f"\nIP Address: {ip_info}" + Colors.ENDC)
        
        # Reverse DNS Lookup
        r_dns = reverse_dns_lookup(ip_info)
        print(Colors.OKCYAN + f"\nReverse DNS Lookup: {r_dns}" + Colors.ENDC)

        # Get Geolocation Info
        geolocation_info = get_ip_geolocation(ip_info)
        print(Colors.HEADER + "\n -----------IP Geolocation Info:-----------" + Colors.ENDC)
        if geolocation_info:
            print(tabulate(geolocation_info.items(), headers=['Key', 'Value'], tablefmt='grid'))
        else:
            print(Colors.FAIL + "No geolocation information available." + Colors.ENDC)
    else:
        print(Colors.FAIL + "\nCould not resolve IP address." + Colors.ENDC)

    # Get WHOIS Info
    whois_info = get_whois_info(domain)
    print(Colors.HEADER + "\n -----------WHOIS Information: -----------" + Colors.ENDC)
    print(Colors.OKGREEN + whois_info + Colors.ENDC)

    # Get DNS Info
    dns_info = get_dns_records(domain)
    print(Colors.HEADER + "\n -----------DNS Information: -----------" + Colors.ENDC)
    print(tabulate(dns_info.items(), headers=['Record Type', 'Values'], tablefmt='grid'))

    # Find Shared DNS Servers
    shared_dns_servers = find_shared_dns_servers(domain)
    print(Colors.HEADER + "\n -----------Shared DNS Servers: -----------" + Colors.ENDC)
    if isinstance(shared_dns_servers, set):
        for dns in shared_dns_servers:
            print(Colors.OKCYAN + f"          > {dns}" + Colors.ENDC)
    else:
        print(Colors.FAIL + f"          > {shared_dns_servers}" + Colors.ENDC)

    # Get Web Server Info
    web_server_info = get_web_server_info(domain)
    print(Colors.HEADER + "\n -----------Web Server Information: -----------" + Colors.ENDC)
    print(Colors.OKGREEN + web_server_info + Colors.ENDC)

    # Validate DNSSEC
    dnssec_info = validate_dnssec(domain)
    print(Colors.HEADER + "\n -----------DNSSEC Validation: -----------" + Colors.ENDC)
    print(Colors.OKGREEN + dnssec_info + Colors.ENDC)

    # Get SSL/TLS Certificate Info
    ssl_info = get_ssl_certificate_info(domain)
    print(Colors.HEADER + "\n -----------SSL/TLS Certificate Info: -----------" + Colors.ENDC)
    if isinstance(ssl_info, dict):
        print(tabulate(ssl_info.items(), headers=['Field', 'Value'], tablefmt='grid'))
    else:
        print(Colors.FAIL + f"          > {ssl_info}" + Colors.ENDC)

    # Run Nmap
    nmap_result = run_nmap(domain)
    print(Colors.HEADER + "\n -----------Nmap Results: -----------" + Colors.ENDC)
    print(Colors.OKGREEN + nmap_result + Colors.ENDC)

    # Find DNS Host Records
    host_records = find_dns_host_records(domain)
    print(Colors.HEADER + "\n -----------DNS Host Records: -----------" + Colors.ENDC)
    print(tabulate(host_records.items(), headers=['Record Type', 'Values'], tablefmt='grid'))

if __name__ == "__main__":
    main()
