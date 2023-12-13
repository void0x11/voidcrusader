"""
The dns_enumeration module is designed to perform DNS enumeration for a given domain. 
It queries DNS records to extract information like A, MX, and NS records, which are essential for 
understanding the DNS configuration of the domain.
"""

import socket

class DNSEnumeration:
    """
    This class performs DNS enumeration for a given domain. 
    DNS enumeration is the process of querying the DNS system to find DNS records such as A records.
    
    Attributes:
        domain (str): The domain name to perform enumeration on.
    """

    def __init__(self, domain):
        """
        Initialize the DNS enumeration with a specific domain.

        Args:
            domain (str): The domain name to perform enumeration on.
        """

        self.domain = domain

    def get_a_record(self):
        """
        Retrieves the A record for the specified domain. An A record maps a domain name to an IPv4 address.

        Returns:
            str: The A record if found, otherwise a message indicating the record was not found.
        """

        try:
            ip_address = socket.gethostbyname(self.domain)
            return f"A record: {ip_address}"
        except socket.gaierror:
            return "A record: Not found"
