"""
The network_scanner module utilizes the nmap tool to perform different types of network scans. 
It includes capabilities for TCP SYN scans, UDP scans, stealth ping scans, and host discovery, 
allowing for a comprehensive overview of the network.
"""

import nmap

class NetworkScanner:
    """
    A class that utilizes nmap to perform various types of network scans.
    The class provides functionalities for TCP SYN scan, UDP scan, stealth ping scan,
    and host discovery.

    Methods:
        tcp_syn_scan: Perform a TCP SYN scan.
        udp_scan: Perform a UDP scan.
        stealth_ping_scan: Perform a stealth ping scan.
        host_discovery: Perform host discovery.
    """

    def __init__(self):
        """
        Initialize the NetworkScanner with an instance of nmap.PortScanner.
        """
        self.scanner = nmap.PortScanner()

    def tcp_syn_scan(self, target):
        """
        Perform a TCP SYN scan (half-open scan) on the specified target.

        Args:
            target (str): The target IP or IP range to scan.

        Returns:
            dict: The scan results.
        """
        return self.scanner.scan(hosts=target, arguments='-sS')

    def udp_scan(self, target):
        """
        Perform a UDP scan on the specified target.

        Args:
            target (str): The target IP or IP range to scan.

        Returns:
            dict: The scan results.
        """
        return self.scanner.scan(hosts=target, arguments='-sU')

    def stealth_ping_scan(self, target):
        """
        Perform a stealth ping scan to check if the target host(s) are up 
        without sending any packets to the target hosts.

        Args:
            target (str): The target IP or IP range to scan.

        Returns:
            dict: The scan results.
        """
        return self.scanner.scan(hosts=target, arguments='-sP')

    def host_discovery(self, target):
        """
        Perform a host discovery scan, which checks if the host(s) are up 
        without port scanning.

        Args:
            target (str): The target IP or IP range to scan.

        Returns:
            dict: The scan results.
        """
        return self.scanner.scan(hosts=target, arguments='-sn')
