"""
The subdomain_enumeration module provides methods to enumerate subdomains of a given domain. 
It checks for the existence of common subdomains and verifies their activity through DNS resolution 
and optional HTTP checks.
"""

import socket
import http.client
from urllib.parse import urlparse

class SubdomainEnumeration:
    """
    A class to enumerate subdomains for a given domain.
    
    This class attempts to find subdomains by checking DNS records and making HTTP requests. 
    It also includes functionality to detect wildcard DNS setups.

    Attributes:
        domain (str): The domain to enumerate subdomains for.
        subdomains (list): A list of potential subdomains to check.
        wildcard_detected (bool): Flag to indicate if wildcard DNS is detected.
    """

    def __init__(self, domain, subdomain_list):
        """
        Initialize the SubdomainEnumeration with a domain and a list of potential subdomains.

        Args:
            domain (str): The domain to enumerate subdomains for.
            subdomain_list (list): A list of potential subdomains to check.
        """
        self.domain = domain
        self.subdomains = subdomain_list
        self.wildcard_detected = False

    def check_wildcard_dns(self):
        """
        Check for wildcard DNS setup in the domain.

        If a wildcard DNS is detected, any subdomain query will resolve to an IP address,
        making subdomain enumeration meaningless.
        """
        try:
            socket.gethostbyname(f"unlikely-subdomain-for-wildcard-check.{self.domain}")
            self.wildcard_detected = True
        except socket.gaierror:
            self.wildcard_detected = False

    def http_check(self, subdomain):
        """
        Perform an HTTP request to check if the subdomain is active.

        Args:
            subdomain (str): The subdomain to check.

        Returns:
            bool: True if the subdomain responds with an HTTP status code less than 400, False otherwise.
        """
        parsed_url = urlparse(f"http://{subdomain}")
        conn = http.client.HTTPConnection(parsed_url.netloc, timeout=10)
        try:
            conn.request("HEAD", parsed_url.path)
            response = conn.getresponse()
            if response.status < 400:
                return True
        except (socket.gaierror, http.client.HTTPException):
            return False
        finally:
            conn.close()
        return False

    def enumerate(self):
        """
        Enumerate subdomains for the domain.

        This function checks each subdomain in the list to see if it resolves to an IP address 
        and if it responds to an HTTP request.

        Returns:
            list: A list of found subdomains.
        """
        if self.wildcard_detected:
            return ["Wildcard DNS detected. Enumeration is not meaningful."]

        found_subdomains = []
        for subdomain in self.subdomains:
            fqdn = f"{subdomain}.{self.domain}"
            try:
                socket.gethostbyname(fqdn)
                if self.http_check(fqdn):
                    found_subdomains.append(fqdn)
            except socket.gaierror:
                continue
        return found_subdomains
