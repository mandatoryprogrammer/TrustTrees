import secrets

import dns.flags
import dns.rcode
import dns.rdatatype
import dns.resolver

from . import global_state
from .constants import (
    IPV6_ENABLED,
    MAX_RECURSION_DEPTH,
    ROOT_SERVERS,
)
from .utils import is_authoritative


def _get_random_root_ns_set():
    return secrets.choice(ROOT_SERVERS)


def _wrap_ns_query(hostname, nameserver_ip, nameserver_hostname):
    """
    This writes to global_state.MASTER_DNS_CACHE, which is
    later read from in _draw_graph_from_cache() of draw.py
    """
    # Normalize input query data
    hostname = hostname.lower()

    # Create cache key and check if we already cached this response
    cache_key = f'{hostname}|ns|{nameserver_ip}|{nameserver_hostname}'
    if cache_key in global_state.MASTER_DNS_CACHE:
        return global_state.MASTER_DNS_CACHE[cache_key]

    global_state.MASTER_DNS_CACHE[cache_key] = _ns_query(
        hostname,
        nameserver_ip,
        nameserver_hostname,
    )
    return global_state.MASTER_DNS_CACHE[cache_key]


def _dns_query(target_hostname, query_type, target_nameserver):
    res = dns.resolver.Resolver(configure=False)
    res.nameservers = [target_nameserver]
    result = res.query(
        qname=target_hostname,
        rdtype=query_type,
        raise_on_no_answer=False,
    )
    return result


def _try_to_get_first_ip_for_hostname(hostname):
    """
    :returns: string
    e.g.
        "1.2.3.4" or ""
    """
    try:
        answer = _dns_query(
            hostname,
            query_type='A',
            target_nameserver=secrets.choice(global_state.RESOLVERS),
        )
        if answer.rrset:
            return str(answer.rrset[0])
    except (
        dns.resolver.NoNameservers,
        dns.resolver.NXDOMAIN,
        dns.resolver.Timeout,
        dns.resolver.YXDOMAIN,
    ):
        pass
    return ''


def _ns_query(hostname, nameserver_ip, nameserver_hostname):
    """
    Performs the NS query.

    Writes to
        global_state.AUTHORITATIVE_NS_LIST,
        global_state.NS_IP_MAP
        and global_state.QUERY_ERROR_LIST
    which is later read from in _get_graph_data_for_ns_result() in draw.py

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
        ns_result = _dns_query(
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
        global_state.QUERY_ERROR_LIST.append(
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

            # Store this glue record in our global_state.NS_IP_MAP for later
            global_state.NS_IP_MAP[ns_hostname] = ns_ip

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
                ns_hostname not in global_state.AUTHORITATIVE_NS_LIST
            ):
                global_state.AUTHORITATIVE_NS_LIST.append(ns_hostname)

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
                if not global_state.NS_IP_MAP[ns_hostname]:
                    # Send an A query to a resolver to get the IP
                    global_state.NS_IP_MAP[ns_hostname] = _try_to_get_first_ip_for_hostname(
                        ns_hostname,
                    )

                if global_state.NS_IP_MAP[ns_hostname]:
                    ns_dict['ns_ip'] = global_state.NS_IP_MAP[ns_hostname]

                return_dict[corresponding_key].append(ns_dict)

                # If this was an authoritative answer, we need to save that for graphing
                if (
                    is_authoritative(return_dict['flags'])
                    and
                    ns_hostname not in global_state.AUTHORITATIVE_NS_LIST
                ):
                    global_state.AUTHORITATIVE_NS_LIST.append(ns_hostname)

    return return_dict


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
            ns_result = _wrap_ns_query(
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


def enumerate_nameservers(domain_name):
    if not domain_name.endswith('.'):
        domain_name += '.'

    # Get random root server and query it to bootstrap our walk of the chain
    root_ns_set = _get_random_root_ns_set()
    tld_ns_result = _wrap_ns_query(
        hostname=domain_name,
        nameserver_ip=root_ns_set['ip'],
        nameserver_hostname=root_ns_set['hostname'],
    )
    _recursively_enumerate_nameservers(
        domain_name,
        previous_ns_result=tld_ns_result,
    )
