"""
The whois_lookup module is used to perform WHOIS lookups for domain names. It queries WHOIS servers 
to retrieve the registered information of a domain, such as registrar, creation date, and contact details.
"""

import socket

class WhoisLookup:
    """
    A class to perform a WHOIS lookup for a given domain.
    
    WHOIS lookup is a query and response protocol used for querying databases 
    that store registered users or assignees of an Internet resource, such as a domain name.

    Attributes:
        server (str): The WHOIS server to connect to for the lookup.
    """

    def __init__(self, server="whois.iana.org"):
        """
        Initialize the WhoisLookup with a specified WHOIS server.

        Args:
            server (str, optional): The WHOIS server to connect to. Defaults to "whois.iana.org".
        """
        self.server = server

    def lookup(self, domain):
        """
        Perform a WHOIS lookup for the specified domain.

        Args:
            domain (str): The domain name to perform the WHOIS lookup on.

        Returns:
            str: The WHOIS lookup result as a string.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.server, 43))
            s.send((domain + "\r\n").encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            return response.decode()
