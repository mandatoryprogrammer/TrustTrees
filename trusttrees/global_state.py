from collections import defaultdict


AWS_CREDS_FILE = ''
DNSIMPLE_ACCESS_TOKEN = ''
GANDI_API_V4_KEY = ''
GANDI_API_V5_KEY = ''

CHECK_DOMAIN_AVAILABILITY = True

PREVIOUS_EDGES = set()
RESOLVERS = []

"""
Saved results of DNS queries, key format is the following:

KEY = FQDN_QUERY_NAME|QUERY_TYPE|NS_TARGET_IP

e.g.
    "google.com.|ns|192.168.1.1"
"""
MASTER_DNS_CACHE = {}

"""
This creates an easy map of nameserver names to one of their IP addresses.

It is used to check for nameservers without any IP addresses.

e.g.
    {
        "ns1.example.com.": "192.168.1.1",
        "ns2.example.com.": "",
        ...
    }
"""
NS_IP_MAP = defaultdict(str)

"""
A simple list of nameservers which were returned with the authoritative answer flag set.

Used for graphing to make it clear where the flow of queries ends.

We use a list instead of a set to preserve ordering slightly better.
"""
AUTHORITATIVE_NS_LIST = []

"""
A list of DNS errors returned whilst querying nameservers.

This is used in graphing to show where the flow breaks.
"""
QUERY_ERROR_LIST = []
