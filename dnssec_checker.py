"""
This dnssec_checker module is used for checking the DNS Security Extensions (DNSSEC) status of a domain. 
It queries for DNSKEY records and assesses whether DNSSEC is properly implemented and enabled for the domain.
"""

import dns.resolver

class DNSSECChecker:
    """
    This class performs DNS Security Extensions (DNSSEC) checking for a given domain.
    DNSSEC provides authentication of DNS data, authenticated denial of existence, 
    and data integrity, but not confidentiality.

    Attributes:
        domain (str): The domain name to perform DNSSEC checking on.
    """

    def __init__(self, domain):
        """
        Initialize the DNSSEC checker with a specific domain.

        Args:
            domain (str): The domain name to perform DNSSEC checking on.
        """
        self.domain = domain

    def check_dnssec(self):
        """
        Checks the DNSSEC status of the domain by querying for DNSKEY records. 
        It evaluates if DNSSEC is enabled and identifies if the DNSKEY record is 
        present as a Key Signing Key (KSK) or Zone Signing Key (ZSK).

        Returns:
            str: A message indicating the status of DNSSEC for the domain.
        """
        try:
            # Query for DNSKEY records
            answers = dns.resolver.resolve(self.domain, 'DNSKEY')
            if answers:
                # Check for KSK and ZSK flags
                for rdata in answers:
                    if rdata.flags & 256:  # Checking for KSK
                        return "DNSSEC is enabled and KSK DNSKEY record is present."
                    elif rdata.flags & 128:  # Checking for ZSK
                        return "DNSSEC is enabled and ZSK DNSKEY record is present."
                return "DNSSEC is enabled but no specific DNSKEY record found."
            else:
                return "DNSSEC not enabled."
        except dns.resolver.NoAnswer:
            return "No DNSKEY record found."
        except dns.resolver.NXDOMAIN:
            return "Domain does not exist."
        except dns.exception.Timeout:
            return "Query timed out."
        except dns.resolver.NoNameservers:
            return "No nameservers available for the domain."
