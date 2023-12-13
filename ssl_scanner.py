"""
The ssl_scanner module provides functionality to scan a specified host and port for SSL/TLS support.
It checks if a secure communication protocol is supported by attempting to establish an SSL/TLS connection.
"""

import ssl
import socket

class TLSScanner:
    """
    A class that checks if a specified host supports SSL/TLS on a given port.
    
    The class attempts to establish an SSL/TLS connection to the host to determine
    if the host supports secure communication protocols.

    Attributes:
        host (str): The hostname or IP address of the server to scan.
        port (int): The port number to check for SSL/TLS support.
    """

    def __init__(self, host, port):
        """
        Initialize the TLSScanner with a host and port.

        Args:
            host (str): The hostname or IP address of the server to scan.
            port (int): The port number to check for SSL/TLS support.
        """
        self.host = host
        self.port = port

    def scan(self):
        """
        Perform an SSL/TLS scan on the specified host and port.

        Tries to establish an SSL/TLS connection to the server. If the handshake
        is successful, it implies that the server supports SSL/TLS.

        Returns:
            bool: True if the server supports SSL/TLS, False otherwise.
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.host, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    ssock.do_handshake()
                    return True
        except ssl.SSLError:
            return False
