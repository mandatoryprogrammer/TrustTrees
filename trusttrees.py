#!/usr/bin/env python
from __future__ import print_function

import argparse
import errno
import os
import random
import subprocess
import time
from collections import defaultdict

import dns.flags
import dns.rcode
import dns.rdatatype
import dns.resolver
import pygraphviz
import requests
import tldextract
import xmlrpclib

gandi_api_v4 = xmlrpclib.ServerProxy(uri='https://rpc.gandi.net/xmlrpc/')
GANDI_API_V4_KEY = ''
GANDI_API_V5_KEY = ''

BLUE = '#0099ff'
GRAY = '#a3a3a3'
RED = '#ff0000'
ORANGE = '#ff7700'
YELLOW = '#fff200'

ROOT_SERVERS = (
    {
        'ip': '198.41.0.4',
        'hostname': 'a.root-servers.net.',
    },
    {
        'ip': '192.228.79.201',
        'hostname': 'b.root-servers.net.',
    },
    {
        'ip': '192.33.4.12',
        'hostname': 'c.root-servers.net.',
    },
    {
        'ip': '199.7.91.13',
        'hostname': 'd.root-servers.net.',
    },
    {
        'ip': '192.203.230.10',
        'hostname': 'e.root-servers.net.',
    },
    {
        'ip': '192.5.5.241',
        'hostname': 'f.root-servers.net.',
    },
    {
        'ip': '192.112.36.4',
        'hostname': 'g.root-servers.net.',
    },
    {
        'ip': '198.97.190.53',
        'hostname': 'h.root-servers.net.',
    },
    {
        'ip': '192.36.148.17',
        'hostname': 'i.root-servers.net.',
    },
    {
        'ip': '192.58.128.30',
        'hostname': 'j.root-servers.net.',
    },
    {
        'ip': '193.0.14.129',
        'hostname': 'k.root-servers.net.',
    },
    {
        'ip': '199.7.83.42',
        'hostname': 'l.root-servers.net.',
    },
    {
        'ip': '202.12.27.33',
        'hostname': 'm.root-servers.net.',
    },
)

DNS_WATCH_RESOLVER = '84.200.69.80'
DOMAIN_AVAILABILITY_CACHE = {}
IPV6_ENABLED = False
MAX_RECURSION_DEPTH = 4
PREVIOUS_EDGES = []

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


def can_register_with_gandi_api_v4(input_domain):
    """
    :returns: bool
    if input_domain is available for registration
    """
    for _ in range(10):
        result = gandi_api_v4.domain.available(
            GANDI_API_V4_KEY,
            [input_domain],
        )
        if result[input_domain] != 'pending':
            break
        time.sleep(1)

    return result[input_domain] == 'available'


def can_register_with_gandi_api_v5(input_domain):
    """
    For more information, please see
    https://api.gandi.net/docs/domains/

    :returns: bool
    if input_domain is available for registration
    """
    for _ in range(10):
        response = requests.get(
            url='https://api.gandi.net/v5/domain/check',
            params={
                'name': input_domain,
            },
            headers={
                'Authorization': 'Apikey {}'.format(GANDI_API_V5_KEY),
            },
        )
        assert response.status_code == 200

        if 'products' not in response.json():
            return False
        assert len(response.json()['products']) == 1

        status = response.json()['products'][0]['status']

        if status != 'pending':
            break
        time.sleep(1)

    return status == 'available'


def is_domain_available(input_domain):
    """
    Called if Gandi API key is provided.

    :returns: bool
    """
    if input_domain.endswith('.'):
        input_domain = input_domain[:-1]

    if input_domain in DOMAIN_AVAILABILITY_CACHE:
        return DOMAIN_AVAILABILITY_CACHE[input_domain]

    print('[ STATUS ] Checking if ' + input_domain + ' is available...')

    if GANDI_API_V4_KEY:
        domain_available = can_register_with_gandi_api_v4(input_domain)
    else:
        domain_available = can_register_with_gandi_api_v5(input_domain)

    DOMAIN_AVAILABILITY_CACHE[input_domain] = domain_available

    return domain_available


def get_base_domain(input_hostname):
    """
    :type input_hostname: str
    e.g.
        "ns2.foo.com."

    :returns:string
    e.g.
        foo.com.
    """
    tldexact_parts = tldextract.extract('http://' + input_hostname)
    return '{}.{}.'.format(
        tldexact_parts.domain,
        tldexact_parts.suffix,
    )


def get_random_root_ns_set():
    return random.choice(ROOT_SERVERS)


def dns_query(target_hostname, query_type, target_nameserver):
    res = dns.resolver.Resolver(configure=False)
    res.nameservers = [target_nameserver]
    result = res.query(
        qname=target_hostname,
        rdtype=query_type,
        raise_on_no_answer=False,
    )
    return result


def is_authoritative(flags):
    return 'AA' in flags


def ns_query(hostname, nameserver_ip, nameserver_hostname):
    """
    This writes to MASTER_DNS_CACHE, which is
    later read from in draw_graph_from_cache()
    """
    if not hostname.endswith('.'):
        hostname += '.'

    # Normalize input query data
    hostname = hostname.lower()

    # Create cache key and check if we already cached this response
    cache_key = '{}|ns|{}|{}'.format(
        hostname,
        nameserver_ip,
        nameserver_hostname,
    )
    if cache_key in MASTER_DNS_CACHE:
        return MASTER_DNS_CACHE[cache_key]

    MASTER_DNS_CACHE[cache_key] = _ns_query(
        hostname,
        nameserver_ip,
        nameserver_hostname,
    )
    return MASTER_DNS_CACHE[cache_key]


def _ns_query(hostname, nameserver_ip, nameserver_hostname):
    """
    Performs the NS query.

    Writes to
        AUTHORITATIVE_NS_LIST,
        NS_IP_MAP
        and QUERY_ERROR_LIST
    which is later read from in get_graph_data_for_ns_result()

    :returns: dictionary
    e.g.
         {
             'nameserver_ip': '1.2.3.4',
             'rcode_string': 'NOERROR',
             'flags': [
                 'QR',
                 'RD'
             ],
             'authority_ns': [
                 {
                     'ns_ip': '5.6.7.8',
                     'hostname': 'foo.',
                     'ns_hostname': 'demand.alpha.aridns.net.au.',
                     'ttl': 172800
                 },
                 ...
            ],
            'additional_ns': [],
            'answer_ns': [],
            'hostname': 'bar.foo.',
            'rcode': 0,
            'success': True,
            'nameserver_hostname': 'g.root-servers.net.'
        }
    """
    print(
        "[ STATUS ] Querying nameserver '{}/{}' for NS of '{}'".format(
            nameserver_ip,
            nameserver_hostname,
            hostname,
        ),
    )
    dns_query_error = None
    return_dict = {
        'hostname': hostname,
        'nameserver_hostname': nameserver_hostname,
        'nameserver_ip': nameserver_ip,
        'additional_ns': [],
        'authority_ns': [],
        'answer_ns': [],
        'flags': [],
        'success': False,
    }

    try:
        ns_result = dns_query(
            hostname,
            query_type='NS',
            target_nameserver=nameserver_ip,
        )
    except dns.resolver.NoNameservers:
        # TODO: This fucking blows, figure out a way to do this without an exception
        dns_query_error = 'FATAL_ERROR'
        return_dict['rcode'] = -1
    except dns.resolver.NXDOMAIN:
        dns_query_error = 'NXDOMAIN'
        return_dict['rcode'] = dns.rcode.NXDOMAIN
    except dns.resolver.Timeout:
        dns_query_error = 'TIMEOUT'
        return_dict['rcode'] = -1
    except dns.resolver.YXDOMAIN:
        dns_query_error = 'YXDOMAIN'
        return_dict['rcode'] = dns.rcode.YXDOMAIN

    if dns_query_error:
        return_dict['rcode_string'] = dns_query_error
        QUERY_ERROR_LIST.append(
            {
                'hostname': hostname,
                'error': dns_query_error,
                'ns_hostname': nameserver_hostname,
            },
        )
        return return_dict

    # If we have made it this far, we can mark the response as successful
    return_dict['success'] = True

    return_dict['flags'] = dns.flags.to_text(
        ns_result.response.flags,
    ).split(' ')
    return_dict['rcode'] = ns_result.response.rcode()
    return_dict['rcode_string'] = dns.rcode.to_text(return_dict['rcode'])

    # ADDITIONAL section of NS answer
    for rrset in ns_result.response.additional:
        if rrset.rdtype != dns.rdatatype.NS:
            continue
        for rrset_value in rrset.items:
            if (
                ':' in str(rrset_value)
                and
                not IPV6_ENABLED
            ):
                continue
            ns_ip = str(rrset_value).lower()
            ns_hostname = str(rrset.name).lower()

            # Store this glue record in our NS_IP_MAP for later
            NS_IP_MAP[ns_hostname] = ns_ip

            return_dict['additional_ns'].append(
                {
                    'ns_ip': ns_ip,
                    'ttl': int(rrset.ttl),
                    'ns_hostname': ns_hostname,
                },
            )

            # If this was an authoritative answer, we need to save that for graphing
            if (
                is_authoritative(return_dict['flags'])
                and
                ns_hostname not in AUTHORITATIVE_NS_LIST
            ):
                AUTHORITATIVE_NS_LIST.append(ns_hostname)

    for section_of_NS_answer, corresponding_key in (
        (
            ns_result.response.authority,
            'authority_ns',
        ),
        (
            ns_result.response.answer,
            'answer_ns',
        ),
    ):
        for rrset in section_of_NS_answer:
            if rrset.rdtype != dns.rdatatype.NS:
                continue
            for rrset_value in rrset.items:
                ns_hostname = str(rrset_value).lower()

                ns_dict = {
                    'ns_hostname': ns_hostname,
                    'ttl': int(rrset.ttl),
                    'hostname': str(rrset.name).lower(),
                }

                # Since NS results sometimes do not have a glue record, we have to retrieve it..
                # If ns_hostname is not in our DNS cache
                if not NS_IP_MAP[ns_hostname]:
                    # Send an A query to DNS_WATCH_RESOLVER to get the IP
                    NS_IP_MAP[ns_hostname] = try_to_get_first_ip_for_hostname(
                        ns_hostname,
                    )

                if NS_IP_MAP[ns_hostname]:
                    ns_dict['ns_ip'] = NS_IP_MAP[ns_hostname]

                return_dict[corresponding_key].append(ns_dict)

                # If this was an authoritative answer, we need to save that for graphing
                if (
                    is_authoritative(return_dict['flags'])
                    and
                    ns_hostname not in AUTHORITATIVE_NS_LIST
                ):
                    AUTHORITATIVE_NS_LIST.append(ns_hostname)

    return return_dict


def enumerate_nameservers(domain_name):
    if not domain_name.endswith('.'):
        domain_name += '.'

    # First get a random root server and query it to bootstrap our walk of the chain
    root_ns_set = get_random_root_ns_set()
    tld_ns_result = ns_query(
        hostname=domain_name,
        nameserver_ip=root_ns_set['ip'],
        nameserver_hostname=root_ns_set['hostname'],
    )
    _recursively_enumerate_nameservers(
        domain_name,
        previous_ns_result=tld_ns_result,
    )


def _recursively_enumerate_nameservers(domain_name, previous_ns_result, depth=0):
    """
    Take the previous NS result and do NS queries against all of the returned nameservers.
    """
    for section_of_NS_answer in (
        'additional_ns',
        'answer_ns',
        'authority_ns',
    ):
        for ns_rrset in previous_ns_result[section_of_NS_answer]:
            if (
                section_of_NS_answer != 'additional_ns'
                and
                'ns_ip' not in ns_rrset
            ):
                continue
            ns_result = ns_query(
                hostname=domain_name,
                nameserver_ip=ns_rrset['ns_ip'],
                nameserver_hostname=ns_rrset['ns_hostname'],
            )
            if depth < MAX_RECURSION_DEPTH:
                _recursively_enumerate_nameservers(
                    domain_name,
                    previous_ns_result=ns_result,
                    depth=depth + 1,
                )


def draw_graph_from_cache(target_hostname):
    """
    Iterates through MASTER_DNS_CACHE, and calls get_graph_data_for_ns_result()

    :returns: string
    For pygraphviz.AGraph()
    """
    GRAPH_DATA = (
        """
        digraph G {{
        graph [
            label=\"{} DNS Trust Graph\",
            labelloc="t",
            pad="3",
            nodesep="1",
            ranksep="5",
            fontsize=50
        ];
        edge[arrowhead=vee, arrowtail=inv, arrowsize=.7]
        concentrate=true;
        """.format(target_hostname)
    )

    for cache_key, ns_result in MASTER_DNS_CACHE.iteritems():
        print("[ STATUS ] Building '" + cache_key + "'...")
        for section_of_NS_answer in (
            'additional_ns',
            'authority_ns',
            'answer_ns',
        ):
            GRAPH_DATA += get_graph_data_for_ns_result(
                ns_list=ns_result[section_of_NS_answer],
                ns_result=ns_result,
            )

    GRAPH_DATA += '\n}'
    return GRAPH_DATA


def get_graph_data_for_ns_result(ns_list, ns_result):
    return_graph_data_string = ''

    for ns_rrset in ns_list:
        potential_edge = (
            ns_result['nameserver_hostname'] + '->' + ns_rrset['ns_hostname']
        )

        if potential_edge not in PREVIOUS_EDGES:
            PREVIOUS_EDGES.append(potential_edge)
            return_graph_data_string += (
                '"{}" -> "{}" [shape=ellipse]'.format(
                    ns_result['nameserver_hostname'],
                    ns_rrset['ns_hostname'],
                )
            )

            return_graph_data_string += (
                '[label=<<i>{}?</i><br /><font point-size="10">{}</font>>] '.format(
                    ns_result['hostname'],
                    ns_result['rcode_string'],
                )
            )

            if is_authoritative(ns_result['flags']):
                return_graph_data_string += '[color="{}"] '.format(BLUE)
            else:
                return_graph_data_string += '[style="dashed", color="{}"] '.format(
                    GRAY,
                )

            return_graph_data_string += ';\n'

    # Make all nameservers which were specified with an AA flag blue
    for ns_hostname in AUTHORITATIVE_NS_LIST:
        return_graph_data_string += (
            '"{}" [shape=ellipse, style=filled, fillcolor="{}"];\n'.format(
                ns_hostname,
                BLUE,
            )
        )

    # Make all nameservers without any IPs red because they might be vulnerable
    for ns_hostname, ns_hostname_ip in NS_IP_MAP.iteritems():
        if not ns_hostname_ip:
            return_graph_data_string += (
                '"{}" [shape=ellipse, style=filled, fillcolor="{}"];\n'.format(
                    ns_hostname,
                    RED,
                )
            )

        base_domain = get_base_domain(ns_hostname)
        if (
            (
                GANDI_API_V4_KEY
                or
                GANDI_API_V5_KEY
            )
            and
            is_domain_available(base_domain)
        ):
            node_name = "Base domain '" + base_domain + "' unregistered!"
            potential_edge = ns_hostname + '->' + node_name
            if potential_edge not in PREVIOUS_EDGES:
                PREVIOUS_EDGES.append(potential_edge)
                return_graph_data_string += (
                    '"{}" -> "{}";\n'.format(
                        ns_hostname,
                        node_name,
                    )
                )
                return_graph_data_string += (
                    '"{}"[shape=octagon, style=filled, fillcolor="{}"];\n'.format(
                        node_name,
                        ORANGE,
                    )
                )

    # Make nodes for DNS error states encountered like NXDOMAIN, Timeout, etc.
    for query_error in QUERY_ERROR_LIST:
        potential_edge = (
            '{}->{}'.format(
                query_error['ns_hostname'],
                query_error['error'],
            )
        )

        if potential_edge not in PREVIOUS_EDGES:
            PREVIOUS_EDGES.append(potential_edge)
            return_graph_data_string += (
                '"{}" -> "{}" '.format(
                    query_error['ns_hostname'],
                    query_error['error'],
                )
            )
            return_graph_data_string += (
                '[label=<<i>{}?</i><br /><font point-size="10">{}</font>>];\n'.format(
                    query_error['hostname'],
                    query_error['error'],
                ),
            )
            return_graph_data_string += (
                '"{}" [shape=octagon, style=filled, fillcolor="{}"];\n'.format(
                    query_error['error'],
                    YELLOW,
                )
            )

    return return_graph_data_string


def try_to_get_first_ip_for_hostname(hostname):
    """
    :returns: string
    e.g.
        "1.2.3.4"
    """
    try:
        answer = dns_query(
            hostname,
            query_type='A',
            target_nameserver=DNS_WATCH_RESOLVER,
        )
        if answer.rrset:
            return str(answer.rrset[0])
    except Exception:
        pass
    return ''


def create_output_dir():
    try:
        os.mkdir('output')
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


def print_logo():
    print("""
      ______                __ ______
     /_  __/______  _______/ //_  __/_______  ___  _____
      / / / ___/ / / / ___/ __// / / ___/ _ \\/ _ \\/ ___/
     / / / /  / /_/ (__  ) /_ / / / /  /  __/  __(__  )
    /_/ /_/   \\__,_/____/\\__//_/ /_/   \\___/\\___/____/
              Graphing & Scanning DNS Delegation Trees
    """)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Graph out a domain's DNS delegation chain and trust trees!",
    )

    required_group = parser.add_mutually_exclusive_group(required=True)
    required_group.add_argument(
        '-t',
        '--target',
        dest='target_hostname',
        help='Target hostname to generate delegation graph from.',
    )
    required_group.add_argument(
        '-l',
        '--target-list',
        dest='target_hostnames_list',
        help='Input file with a list of target hostnames.',
    )

    parser.add_argument(
        '-o',
        '--open',
        dest='open',
        help='Open the generated graph once run.',
        action='store_true',
    )
    parser.add_argument(
        '--gandi-api-v4-key',
        dest='gandi_api_v4_key',
        help='Gandi API V4 key for checking if nameserver base domains are registerable.',
        metavar='GANDI_API_V4_KEY',
    )
    parser.add_argument(
        '--gandi-api-v5-key',
        dest='gandi_api_v5_key',
        help='Gandi API V5 key for checking if nameserver base domains are registerable.',
        metavar='GANDI_API_V5_KEY',
    )
    parser.add_argument(
        '-x',
        '--export-formats',
        dest='export_formats',
        help='Comma-seperated export formats, e.g: -x png,pdf',
        default='png',
    )
    args = parser.parse_args()

    print_logo()
    create_output_dir()

    if args.gandi_api_v4_key:
        GANDI_API_V4_KEY = args.gandi_api_v4_key
    elif args.gandi_api_v5_key:
        GANDI_API_V5_KEY = args.gandi_api_v5_key

    if args.target_hostname:
        target_hostnames = [args.target_hostname]
    else:
        targets = open(args.target_hostnames_list)
        target_hostnames = [
            hostname
            for hostname in
            targets.read().split('\n')
        ][:-1]  # skip the EOF newline

    for target_hostname in target_hostnames:
        enumerate_nameservers(target_hostname)

        export_formats = [
            extension.strip()
            for extension in
            args.export_formats.split(',')
        ]
        output_graph_file = './output/{}_trust_tree_graph.'.format(
            target_hostname,
        )
        # Render graph image
        grapher = pygraphviz.AGraph(
            draw_graph_from_cache(target_hostname),
        )

        for export_format in export_formats:
            file_name = output_graph_file + export_format
            grapher.draw(file_name, prog='dot')
            if args.open:
                print('[ STATUS ] Opening final graph...')
                subprocess.call(['open', file_name])

        print('[ SUCCESS ] Finished generating graph!')
