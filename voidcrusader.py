"""
This main module serves as the entry point for a network reconnaissance and security analysis tool. 
It integrates various functionalities including network scanning, DNS enumeration, SSL/TLS scanning, 
WHOIS lookup, DNSSEC checking, email address enumeration, subdomain enumeration, and honeypot detection.

The application presents a user-friendly menu-driven interface that allows users to select and 
execute different functionalities. Each selected functionality utilizes one of the integrated modules 
to perform specific tasks like scanning a network, checking SSL/TLS support on a server, performing 
WHOIS lookups, and more. Results from these tasks are either displayed on the console or saved to 
text files for further analysis.

This tool is designed for network administrators, security professionals, and cybersecurity enthusiasts 
to assist in network security assessments, reconnaissance, and educational purposes.

Modules:
    - ssl_scanner: Scans a host for SSL/TLS support.
    - whois_lookup: Performs WHOIS lookups for domain names.
    - dns_enumeration: Enumerates DNS records for a domain.
    - subdomain_enumeration: Enumerates subdomains of a given domain.
    - email_address_enumeration: Validates and enumerates aspects of an email address.
    - honeypot_detector: Detects potential honeypots by analyzing response times and banner information.
    - network_scanner: Performs various network scans using nmap.
    - dnssec_checker: Checks DNSSEC status for a domain.
"""

import ipaddress
import time
import re
from ssl_scanner import TLSScanner
from whois_lookup import WhoisLookup
from dns_enumeration import DNSEnumeration
from subdomain_enumeration import SubdomainEnumeration
from email_address_enumeration import EmailAddressEnumerator
from honeypot_detector import HoneypotDetector
from network_scanner import NetworkScanner
from dnssec_checker import DNSSECChecker

def change_color(color_name):
    """
    Change the terminal text color.

    Args:
    color_name (str): Name of the color to change the text to.

    Returns:
    None
    """

    colors = {
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "magenta": "35",
        "cyan": "36",
        "white": "37",
        "reset": "0"
    }
    color_code = colors.get(color_name, "0")  # Default to reset if color not found
    print(f"\033[{color_code}m", end="")

def reset_color():
    """
    Reset the terminal text color to default.

    Returns:
    None
    """

    print("\033[0m", end="")


def menu ():
    """
    Display the main menu of the tool in the terminal.

    Returns:
    None
    """

    change_color("green")
    print( """
    ██╗░░░██╗░█████╗░██╗██████╗░░█████╗░██████╗░██╗░░░██╗░██████╗░█████╗░██████╗░███████╗██████╗░
    ██║░░░██║██╔══██╗██║██╔══██╗██╔══██╗██╔══██╗██║░░░██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
    ╚██╗░██╔╝██║░░██║██║██║░░██║██║░░╚═╝██████╔╝██║░░░██║╚█████╗░███████║██║░░██║█████╗░░██████╔╝
    ░╚████╔╝░██║░░██║██║██║░░██║██║░░██╗██╔══██╗██║░░░██║░╚═══██╗██╔══██║██║░░██║██╔══╝░░██╔══██╗
    ░░╚██╔╝░░╚█████╔╝██║██████╔╝╚█████╔╝██║░░██║╚██████╔╝██████╔╝██║░░██║██████╔╝███████╗██║░░██║
    ░░░╚═╝░░░░╚════╝░╚═╝╚═════╝░░╚════╝░╚═╝░░╚═╝░╚═════╝░╚═════╝░╚═╝░░╚═╝╚═════╝░╚══════╝╚═╝░░╚═╝

    ================================ Recon by more Nerdy Way ====================================
    """)

    reset_color()
    print("""
    1) Network Scanner
    2) DNS Enumeration
    3) Email Address Enumeration
    4) Subdomain Enumeration
    5) SSL/ TLS scanner
    6) DNSSEC Checker
    7) Whois Lookup
    8) Honeybot Detector
    9) Exit
    """)

DOMAIN_REGEX = re.compile(r'^(?=.{1,253}$)(([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$')


def whoislookup():
    """
    Perform a WHOIS lookup on a domain and save the results to a file.

    Returns:
        None
    """

    domain = input("Enter a domain to lookup: ")
    whois = WhoisLookup()
    result = whois.lookup(domain)

    # Print the result to the console
    print(result)

    # Save the result to a text file
    with open(f"{domain}_whois.txt", "w", encoding='utf-8') as file:
        file.write(result)
        print(f"WHOIS information saved to {domain}_whois.txt")


def ssl_scanner_menu():
    """
    Perform an SSL/TLS scan on a specified host and port.

    Returns:
        None
    """

    host = input("Enter the hostname to scan: ")
    port = int(input("Enter the port to scan: "))

    scanner = TLSScanner(host, port)
    result = scanner.scan()

    if result:
        print(f"{host}:{port} supports SSL/TLS.")
    else:
        print(f"{host}:{port} does not support SSL/TLS.")


def perform_dns_enumeration():
    """
    Perform DNS enumeration on a given domain and save the results to a file.

    Returns:
        None
    """

    domain = input("Enter a domain for DNS enumeration: ")
    if not DOMAIN_REGEX.match(domain):
        print("Invalid domain name. Please enter a valid domain.")
        return

    dns_enum = DNSEnumeration(domain)
    a_record = dns_enum.get_a_record()
    print(a_record)
    # Additional DNS record results can be printed here

    with open(f"{domain}_dns_enum.txt", "w", encoding='utf-8') as file:
        file.write(a_record + "\n")
        # Additional DNS record results can be written here
        print(f"DNS enumeration saved to {domain}_dns_enum.txt")


def perform_subdomain_enumeration():
    """
    Perform subdomain enumeration on a given domain and save the results to a file.

    Returns:
        None
    """

    domain = input("Enter the domain for subdomain enumeration: ")

    # Embed a list of common subdomains directly in the script
    common_subdomains = ["www", "mail", "ftp", "blog", "test", "dev", "api", "shop", "server", "cloud", "portal"]

    # Initialize the enumerator with the domain and the subdomain list
    enumerator = SubdomainEnumeration(domain, common_subdomains)
    enumerator.check_wildcard_dns()
    found_subdomains = enumerator.enumerate()

    print("Found Subdomains:")
    for subdomain in found_subdomains:
        print(subdomain)

    # Create a new file for each domain
    with open(f"{domain}_subdomains.txt", "w",encoding='utf-8') as file:
        for subdomain in found_subdomains:
            file.write(f"{subdomain}\n")
        print(f"Subdomain enumeration saved to {domain}_subdomains.txt")


def perform_dnssec_check():
    """
    Perform a DNSSEC check on a given domain and save the results to a file.

    Returns:
        None
    """

    domain = input("Enter the domain for DNSSEC checking: ")
    checker = DNSSECChecker(domain)
    result = checker.check_dnssec()
    print(result)

    with open(f"{domain}_dnssec.txt", "w",encoding='utf-8') as file:
        file.write(result + "\n")
        print(f"DNSSEC information saved to {domain}_dnssec.txt")


def perform_email_address_enumeration():
    """
    Perform email address enumeration on a given email address.

    Returns:
        None
    """

    email = input("Enter the email address for enumeration: ")
    enumerator = EmailAddressEnumerator(email)

    if not enumerator.check_format():
        print("Invalid email format.")
        return

    if enumerator.is_disposable_email():
        print(f"The domain of {email} is a known disposable email provider.")
        return

    mx_record_exists = enumerator.check_mx_record()
    a_record_exists = enumerator.check_a_record()

    if mx_record_exists and a_record_exists:
        print(f"The domain of {email} has valid MX and A records.")
    elif mx_record_exists:
        print(f"The domain of {email} has valid MX records but no A record.")
    elif a_record_exists:
        print(f"The domain of {email} has an A record but no valid MX records.")
    else:
        print(f"The domain of {email} does not have valid MX or A records.")


def is_valid_ip(ip):
    """
    Check if the provided string is a valid IP address or network.

    Args:
        ip (str): The IP address or network to validate.

    Returns:
        bool: True if valid, False otherwise.
    """

    try:
        ipaddress.ip_network(ip, strict=False)  # Accepts single IPs or networks
        return True
    except ValueError:
        return False


def perform_network_scan():
    """
    Perform a network scan based on the user's choice of scan type.

    Returns:
        None
    """

    scanner = NetworkScanner()
    target = input("Enter the target IP or range for scanning: ")

    if not is_valid_ip(target):
        print("Invalid IP address or range.")
        return

    print("Choose the type of scan:")
    print("1. TCP SYN Scan")
    print("2. UDP Scan")
    print("3. Stealth Ping Scan")
    print("4. Host Discovery")
    scan_type = input("Enter the scan type (1-4): ")

    scan_types = {'1': 'tcp_syn_scan', '2': 'udp_scan', '3': 'stealth_ping_scan', '4': 'host_discovery'}
    if scan_type not in scan_types:
        print("Invalid scan type selected")
        return


    scan_method = getattr(scanner, scan_types[scan_type])
    result = scan_method(target)

    output_filename = f"{target.replace('/', '_')}_{scan_types[scan_type]}.txt"
    with open(output_filename, "w",encoding='utf-8') as file:
        for host in result['scan']:
            file.write(f"Host: {host}\n")
            file.write(f"State: {result['scan'][host].get('status', {}).get('state', 'n/a')}\n")
            for proto in result['scan'][host].all_protocols():
                file.write(f"Protocol: {proto}\n")
                lport = result['scan'][host][proto].keys()
                for port in lport:
                    file.write(f"Port: {port}, State: {result['scan'][host][proto][port]['state']}\n")
    print(f"Scan results saved to {output_filename}")


def perform_honeypot_detection():
    """
    Perform a honeypot detection on a given IP and port, and save the results to a file.

    Returns:
        None
    """

    target = input("Enter the target IP for honeypot detection: ")
    port = input("Enter the port number (default is 80): ")
    port = int(port) if port.isdigit() else 80

    detector = HoneypotDetector(target, port)
    result = detector.detect()
    print(result)

    # Define the filename based on the target and port
    output_filename = f"honeypot_detection_{target.replace('.', '_')}_{port}.txt"

    # Write the result to the file
    with open(output_filename, "w", encoding='utf-8') as file:
        file.write(f"Target: {target}\n")
        file.write(f"Port: {port}\n")
        file.write(f"Detection Result: {result}\n")

    print(f"Detection results saved to {output_filename}")


def main():
    """
    Main function to run the application.

    Returns:
        None
    """

    while True:
        menu()
        choice = input("  Choice: ")

        if choice == '1':
            perform_network_scan()
        elif choice == '2':
            perform_dns_enumeration()
        elif choice == '3':
            perform_email_address_enumeration()
        elif choice == '4':
            perform_subdomain_enumeration()
        elif choice == '5':
            ssl_scanner_menu()  # Call the SSL/TLS scanner function
        elif choice == '6':
            perform_dnssec_check()
        elif choice == '7':
            whoislookup()
            time.sleep(5)
        elif choice == '8':
            perform_honeypot_detection()
        elif choice == '9':
            print("Exiting the program.")
            exit(1)

        else:
            print("Invalid choice. Please enter a valid option (1-5).")

if __name__ == "__main__":
    main()
