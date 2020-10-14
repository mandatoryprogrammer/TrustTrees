import errno
import os
from collections import defaultdict

import tldextract

from . import global_state
from .constants import DNS_WATCH_RESOLVER
from .registar_checking import is_domain_available


def clear_global_state():
    """
    See global_state.py for more information
    """
    global_state.PREVIOUS_EDGES = set()
    global_state.MASTER_DNS_CACHE = {}
    global_state.NS_IP_MAP = defaultdict(str)
    global_state.AUTHORITATIVE_NS_LIST = []
    global_state.QUERY_ERROR_LIST = []


def create_output_dir():
    try:
        os.mkdir('output')
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


def _get_base_domain(input_hostname):
    """
    :type input_hostname: string
    e.g.
        "ns2.foo.com."

    :returns: string
    e.g.
        foo.com.
    """
    tldexact_parts = tldextract.extract(f'http://{input_hostname}')
    return f'{tldexact_parts.domain}.{tldexact_parts.suffix}.'


def get_available_base_domains():
    """
    This can mean the domain can be registered and the DNS hijacked!

    :yields: tuple (string, string)
    e.g.
        ("foo.com.", "ns2.foo.com.")
    """
    for ns_hostname in global_state.NS_IP_MAP:
        base_domain = _get_base_domain(ns_hostname)
        if (
            global_state.CHECK_DOMAIN_AVAILABILITY
            and
            is_domain_available(base_domain)
        ):
            yield (base_domain, ns_hostname)


def get_nameservers_with_no_ip():
    """
    Nameservers without any IPs might be vulnerable

    :yields: string
    Nameserver hostnames
    """
    for ns_hostname, ns_hostname_ip in global_state.NS_IP_MAP.items():
        if not ns_hostname_ip:
            yield ns_hostname


def is_authoritative(flags):
    return 'AA' in flags


def print_logo():
    print("""
      ______                __ ______
     /_  __/______  _______/ //_  __/_______  ___  _____
      / / / ___/ / / / ___/ __// / / ___/ _ \\/ _ \\/ ___/
     / / / /  / /_/ (__  ) /_ / / / /  /  __/  __(__  )
    /_/ /_/   \\__,_/____/\\__//_/ /_/   \\___/\\___/____/
              Graphing & Scanning DNS Delegation Trees
    """)


def set_global_state_with_args(args):
    # For domain-check functionality
    if args.aws_creds_filepath:
        global_state.AWS_CREDS_FILE = args.aws_creds_filepath
    elif args.gandi_api_v4_key:
        global_state.GANDI_API_V4_KEY = args.gandi_api_v4_key
    elif args.gandi_api_v5_key:
        global_state.GANDI_API_V5_KEY = args.gandi_api_v5_key
    elif args.dnsimple_api_v2_token:
        global_state.DNSIMPLE_ACCESS_TOKEN = args.dnsimple_api_v2_token
    else:
        global_state.CHECK_DOMAIN_AVAILABILITY = False

    # To use a random resolver every time
    if args.resolvers:
        with open(args.resolvers) as resolvers:
            global_state.RESOLVERS = [
                resolver if resolver else DNS_WATCH_RESOLVER
                for resolver in
                resolvers.read().splitlines()
            ]
    else:
        global_state.RESOLVERS = [DNS_WATCH_RESOLVER]
