#!/usr/bin/env python
from __future__ import print_function

import secrets
import subprocess
import sys

import dns.flags
import dns.rcode
import dns.rdatatype
import dns.resolver
import pygraphviz
import tldextract

from .constants import (
    BLUE,
    DNS_WATCH_RESOLVER,
    GRAY,
    IPV6_ENABLED,
    MAX_RECURSION_DEPTH,
    ORANGE,
    RED,
    ROOT_SERVERS,
    YELLOW,
)
from .global_state import (
    AUTHORITATIVE_NS_LIST,
    AWS_CREDS_FILE,
    CHECK_DOMAIN_AVAILABILITY,
    GANDI_API_V4_KEY,
    GANDI_API_V5_KEY,
    MASTER_DNS_CACHE,
    NS_IP_MAP,
    PREVIOUS_EDGES,
    QUERY_ERROR_LIST,
)
from .registar_checking import is_domain_available
from .usage import parse_args
from .utils import (
    create_output_dir,
    print_logo,
)


def get_base_domain(input_hostname):
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


def get_random_root_ns_set():
    return secrets.choice(ROOT_SERVERS)


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
    cache_key = f'{hostname}|ns|{nameserver_ip}|{nameserver_hostname}'
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

    # Get random root server and query it to bootstrap our walk of the chain
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
        f"""
        digraph G {{
        graph [
            label=\"{target_hostname} DNS Trust Graph\",
            labelloc="t",
            pad="3",
            nodesep="1",
            ranksep="5",
            fontsize=50
        ];
        edge[arrowhead=vee, arrowtail=inv, arrowsize=.7]
        concentrate=true;
        """
    )

    for cache_key, ns_result in MASTER_DNS_CACHE.items():
        print(f"[ STATUS ] Building '{cache_key}'...")
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


def get_nameservers_with_no_ip():
    """
    Nameservers without any IPs might be vulnerable

    :yields: string
    Nameserver hostnames
    """
    for ns_hostname, ns_hostname_ip in NS_IP_MAP.items():
        if not ns_hostname_ip:
            yield ns_hostname


def get_available_base_domains():
    """
    This can mean the domain can be registered and the DNS hijacked!

    :yields: tuple (string, string)
    e.g.
        ("foo.com.", "ns2.foo.com.")
    """
    for ns_hostname in NS_IP_MAP:
        base_domain = get_base_domain(ns_hostname)
        if (
            CHECK_DOMAIN_AVAILABILITY
            and
            is_domain_available(base_domain)
        ):
            yield (base_domain, ns_hostname)


def get_graph_data_for_ns_result(ns_list, ns_result):
    return_graph_data_string = ''

    for ns_rrset in ns_list:
        potential_edge = (
            f"{ns_result['nameserver_hostname']}->{ns_rrset['ns_hostname']}"
        )

        if potential_edge not in PREVIOUS_EDGES:
            PREVIOUS_EDGES.add(potential_edge)
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
                return_graph_data_string += f'[color="{BLUE}"] '
            else:
                return_graph_data_string += f'[style="dashed", color="{GRAY}"] '

            return_graph_data_string += ';\n'

    # Make all nameservers which were specified with an AA flag blue
    for ns_hostname in AUTHORITATIVE_NS_LIST:
        return_graph_data_string += (
            f'"{ns_hostname}" [shape=ellipse, style=filled, fillcolor="{BLUE}"];\n'
        )

    # Make all nameservers without any IPs red because they are probably vulnerable
    for ns_hostname in get_nameservers_with_no_ip():
        return_graph_data_string += (
            f'"{ns_hostname}" [shape=ellipse, style=filled, fillcolor="{RED}"];\n'
        )

    # Make all nameservers with available base domains orange because they are probably vulnerable
    for ns_hostname, base_domain in get_available_base_domains():
        node_name = f"Base domain '{base_domain}' unregistered!"
        potential_edge = f'{ns_hostname}->{node_name}'
        if potential_edge not in PREVIOUS_EDGES:
            PREVIOUS_EDGES.add(potential_edge)
            return_graph_data_string += (
                f'"{ns_hostname}" -> "{node_name}";\n'
            )
            return_graph_data_string += (
                f'"{node_name}"[shape=octagon, style=filled, fillcolor="{ORANGE}"];\n'
            )

    # Make nodes for DNS error states encountered like NXDOMAIN, Timeout, etc.
    for query_error in QUERY_ERROR_LIST:
        potential_edge = (
            f'{query_error["ns_hostname"]}->{query_error["error"]}'
        )

        if potential_edge not in PREVIOUS_EDGES:
            PREVIOUS_EDGES.add(potential_edge)
            return_graph_data_string += (
                f'"{query_error["ns_hostname"]}" -> "{query_error["error"]}" '
            )
            return_graph_data_string += (
                '[label=<<i>{}?</i><br /><font point-size="10">{}</font>>];\n'.format(
                    query_error['hostname'],
                    query_error['error'],
                )
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
        "1.2.3.4" or ""
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


def main(command_line_args=sys.argv[1:]):
    args = parse_args(command_line_args)

    print_logo()
    create_output_dir()

    if args.aws_creds_filepath:
        AWS_CREDS_FILE = args.aws_creds_filepath
    elif args.gandi_api_v4_key:
        GANDI_API_V4_KEY = args.gandi_api_v4_key
    elif args.gandi_api_v5_key:
        GANDI_API_V5_KEY = args.gandi_api_v5_key
    else:
        CHECK_DOMAIN_AVAILABILITY = False

    if args.target_hostname:
        target_hostnames = [args.target_hostname]
    else:
        targets = open(args.target_hostnames_list)
        target_hostnames = [
            hostname
            for hostname in
            targets.read().split('\n')
        ][:-1]  # Skip the EOF newline

    for target_hostname in target_hostnames:
        enumerate_nameservers(target_hostname)

        export_formats = [
            extension.strip()
            for extension in
            args.export_formats.split(',')
        ]
        output_graph_file = f'./output/{target_hostname}_trust_tree_graph'
        # Render graph image
        grapher = pygraphviz.AGraph(
            draw_graph_from_cache(target_hostname),
        )

        for export_format in export_formats:
            filename = f'{output_graph_file}.{export_format}'
            grapher.draw(filename, prog='dot')
            if args.open:
                print('[ STATUS ] Opening final graph...')
                subprocess.call(['open', filename])

        print('[ SUCCESS ] Finished generating graph!')

    return 0


if __name__ == '__main__':
    sys.exit(main())
