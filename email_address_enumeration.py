"""
This module, email_address_enumeration, offers functionalities to validate and enumerate various aspects of an email address. 
It includes checks for the email format, disposable email domains, and DNS record verification (MX and A records) for the email's domain.
"""

import re
import dns.resolver

class EmailAddressEnumerator:
    """
    This class performs various checks on an email address. These checks include
    validating the format of the email, checking if it's from a disposable email provider,
    and verifying the existence of MX and A records for the email's domain.

    Attributes:
        email (str): The email address to be checked.
        email_regex (re.Pattern): A compiled regular expression pattern to validate email format.
        disposable_domains (set): A set of domains considered to be disposable email providers.
    """

    def __init__(self, email):
        """
        Initialize the Email Address Enumerator with an email address.

        Args:
            email (str): The email address to be checked.
        """
        self.email = email
        self.email_regex = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        self.disposable_domains = set(["tempmail.com", "mailinator.com"])  # Example domains

    def check_format(self):
        """
        Validates the format of the email address against a standard email pattern.

        Returns:
            bool: True if the email format is valid, False otherwise.
        """
        return self.email_regex.match(self.email) is not None

    def is_disposable_email(self):
        """
        Checks if the email address is from a known disposable email provider.

        Returns:
            bool: True if the email is from a disposable provider, False otherwise.
        """
        domain = self.email.split('@')[1]
        return domain in self.disposable_domains

    def check_mx_record(self):
        """
        Verifies the existence of MX (Mail Exchange) records for the email's domain.

        Returns:
            bool: True if MX records are found, False otherwise.
        """
        try:
            domain = self.email.split('@')[1]
            answers = dns.resolver.resolve(domain, 'MX')
            return len(answers) > 0
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            return False

    def check_a_record(self):
        """
        Verifies the existence of A (Address) records for the email's domain.

        Returns:
            bool: True if A records are found, False otherwise.
        """
        try:
            domain = self.email.split('@')[1]
            answers = dns.resolver.resolve(domain, 'A')
            return len(answers) > 0
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            return False
