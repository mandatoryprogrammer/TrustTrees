#!/usr/bin/env python
from __future__ import print_function
import dns.resolver
import tldextract
import dns.flags
import dns.rcode
import xmlrpclib
import argparse
import random
import json
import time
import sys
import os
import errno
from pprint import pprint
from subprocess import call as subprocess_call
import pygraphviz as pgv

gandi_api = xmlrpclib.ServerProxy( "https://rpc.gandi.net/xmlrpc/" )

ROOT_SERVERS = [
    {
        "ip": "198.41.0.4",
        "hostname": "a.root-servers.net.",
    },
    {
        "ip": "192.228.79.201",
        "hostname": "b.root-servers.net.",
    },
    {
        "ip": "192.33.4.12",
        "hostname": "c.root-servers.net.",
    },
    {
        "ip": "199.7.91.13",
        "hostname": "d.root-servers.net.",
    },
    {
        "ip": "192.203.230.10",
        "hostname": "e.root-servers.net.",
    },
    {
        "ip": "192.5.5.241",
        "hostname": "f.root-servers.net.",
    }
]

DOMAIN_AVAILABILITY_CACHE = {}
MAX_RECURSION_DEPTH = 4
IPV6_ENABLED = False
DEFAULT_RESOLVER = "84.200.69.80"
PREVIOUS_EDGES = []

"""
Saved results of DNS queries, key format is the following:

KEY = FQDN_QUERY_NAME|QUERY_TYPE|NS_TARGET_IP

Example:
KEY = "google.com.|ns|192.168.1.1"
"""
MASTER_DNS_CACHE = {}

"""
A key/value map of all the glue records we've seen.

This keys an easy map of nameserver names to IP addresses.

Example:
{
    "ns1.example.com.": [ "192.168.1.1", "192.168.2.1" ],
}
"""
NS_IP_MAP = {}

"""
A simple list of nameservers which were returned with the authoratative answer flag set.

Used for graphing to make it clear where the flow of queries ends.
"""
AUTHORITATIVE_NS_LIST = []

"""
A list of DNS errors returned whilst querying nameservers.

This is used in graphing to show where the flow breaks.
"""
QUERY_ERROR_LIST = []

GANDI_API_KEY = ""

def is_domain_available( input_domain ):
    if input_domain.endswith( "." ):
        input_domain = input_domain[:-1]

    if input_domain in DOMAIN_AVAILABILITY_CACHE:
        return DOMAIN_AVAILABILITY_CACHE[ input_domain ]

    print( "[ STATUS ] Checking if " + input_domain + " is available..." )

    result = gandi_api.domain.available( GANDI_API_KEY, [ input_domain ] )
    counter = 0
    while result[ input_domain ] == "pending" and counter < 10:
        counter += 1
        time.sleep( 1 )
        result = gandi_api.domain.available( GANDI_API_KEY, [ input_domain ] )

    domain_available = ( result[ input_domain ] == "available" )

    DOMAIN_AVAILABILITY_CACHE[ input_domain ] = domain_available

    return domain_available

def get_tld_from_domain( input_hostname ):
    tldexact_parts = tldextract.extract( "http://" + input_hostname )
    return tldexact_parts.suffix + "."

def get_base_domain( input_hostname ):
    tldexact_parts = tldextract.extract( "http://" + input_hostname )
    return tldexact_parts.domain + "." + tldexact_parts.suffix + "."

def pprint( input_dict ):
    print( json.dumps( input_dict, sort_keys=True, indent=4, separators=( ",", ": " ) ) )

def dump(obj):
  for attr in dir(obj):
    print( "obj.%s = %s" % (attr, getattr(obj, attr)) )

def get_random_root_ns_set():
    return random.choice( ROOT_SERVERS )

def dns_query( target_hostname, query_type, target_nameserver ):
    res = dns.resolver.Resolver( configure=False )
    res.nameservers = [ target_nameserver ]
    results = res.query( target_hostname, query_type, raise_on_no_answer=False )
    return results

def is_authoratative( flags ):
    return ( "AA" in flags )

def ns_query( hostname, nameserver_ip, nameserver_hostname ):
    if not hostname.endswith( "." ):
        hostname += "."

    # Normalize input query data
    hostname = hostname.lower()

    # Create cache key and check if we have a cached version of this response.
    cache_key = hostname + "|ns|" + nameserver_ip + "|" + nameserver_hostname

    if cache_key in MASTER_DNS_CACHE:
        return MASTER_DNS_CACHE[ cache_key ]

    return_dict = _ns_query( hostname, nameserver_ip, nameserver_hostname )
    MASTER_DNS_CACHE[ cache_key ] = return_dict

    return return_dict

def _ns_query( hostname, nameserver_ip, nameserver_hostname ):
    print( "[ STATUS ] Querying nameserver '" + nameserver_ip + "/" + nameserver_hostname + "' for NS of '" + hostname + "'" )

    """
    Return data in a more sane format.

    {
        "raw": ORIGINAL_RETURNED_VALUE,
        "nameservers": [
            {
                "ip": "",
                "hostname": "",
                "ttl": "",
            }
        ]
    }
    """
    return_dict = {
        "hostname": hostname,
        "nameserver_hostname": nameserver_hostname,
        "nameserver_ip": nameserver_ip,
        "additional_ns": [],
        "authority_ns": [],
        "answer_ns": [],
        "flags": [],
        "success": False,
    }

    dns_query_error_occured = False

    try:
        results = dns_query( hostname, "NS", nameserver_ip )
    except dns.resolver.NXDOMAIN:
        dns_query_error_occured = "NXDOMAIN"
        return_dict[ "rcode" ] = 3
    except dns.resolver.Timeout:
        dns_query_error_occured = "TIMEOUT"
        return_dict[ "rcode" ] = -1
    except dns.resolver.YXDOMAIN:
        dns_query_error_occured = "YXDOMAIN"
        return_dict[ "rcode" ] = 6
    except dns.resolver.NoNameservers:
        # TODO, this fucking blows, figure out a way to do this without an exception.
        dns_query_error_occured = "FATAL_ERROR"
        return_dict[ "rcode" ] = -1

    if dns_query_error_occured:
        return_dict[ "rcode_string" ] = dns_query_error_occured
        QUERY_ERROR_LIST.append({
            "hostname": hostname,
            "error": dns_query_error_occured,
            "ns_hostname": nameserver_hostname
        })
        return return_dict

    # If we've made it this far we can mark the response as successful.
    return_dict[ "success" ] = True

    return_dict[ "flags" ] = dns.flags.to_text( results.response.flags ).split( " " )
    return_dict[ "rcode" ] = results.response.rcode()
    return_dict[ "rcode_string" ] = dns.rcode.to_text( return_dict[ "rcode" ] )

    # ADDITIONAL section of NS answer
    ns_hostnames_with_ip = []
    for rrset in results.response.additional:
        if rrset.rdtype == 2:
            for rrset_value in rrset.items:
                if ( ":" in str( rrset_value ) and IPV6_ENABLED ) or ( not ":" in str( rrset_value ) ):
                    ns_ip = str( rrset_value ).lower()
                    ns_hostname = str( rrset.name ).lower()

                    # Store this glue record in our NS_IP_MAP for later
                    if not ns_hostname in NS_IP_MAP:
                        NS_IP_MAP[ ns_hostname ] = []
                    if not ns_ip in NS_IP_MAP[ ns_hostname ]:
                        NS_IP_MAP[ ns_hostname ].append( ns_ip )

                    ns_hostnames_with_ip.append( str( rrset.name ).lower() )
                    return_dict[ "additional_ns" ].append({
                        "ns_ip": ns_ip,
                        "ttl": int( rrset.ttl ),
                        "ns_hostname": ns_hostname,
                    })

                    # If this was an authoratative answer we need to save that for graphing.
                    if is_authoratative( return_dict[ "flags" ] ) and not ( ns_hostname in AUTHORITATIVE_NS_LIST ):
                        AUTHORITATIVE_NS_LIST.append( ns_hostname )

    # TODO: DRY this up somehow vvv

    # AUTHORITY section of NS answer
    for rrset in results.response.authority:
        if rrset.rdtype == 2:
            for rrset_value in rrset.items:
                ns_hostname = str( rrset_value ).lower()
                # Add this to our NS_IP_MAP as an empty entry
                if not ns_hostname in NS_IP_MAP:
                    NS_IP_MAP[ ns_hostname ] = []

                ns_dict = {
                    "ns_hostname": ns_hostname,
                    "ttl": int( rrset.ttl ),
                    "hostname": str( rrset.name ).lower(),
                }

                # Since NS results sometimes won't have a glue record we will have to retrieve it..
                # First check out own DNS cache, if that fails then just use our resolver to get the IP.
                ns_ip = False

                if len( NS_IP_MAP[ ns_hostname ] ) == 0 :
                    NS_IP_MAP[ ns_hostname ] = get_hostname_ips( ns_hostname )

                if len( NS_IP_MAP[ ns_hostname ] ) > 0 :
                    ns_ip = NS_IP_MAP[ ns_hostname ][0]

                if ns_ip:
                    ns_dict[ "ns_ip" ] = ns_ip

                return_dict[ "authority_ns" ].append( ns_dict )

                # If this was an authoratative answer we need to save that for graphing.
                if is_authoratative( return_dict[ "flags" ] ) and not ( ns_hostname in AUTHORITATIVE_NS_LIST ):
                    AUTHORITATIVE_NS_LIST.append( ns_hostname )

    # ANSWER section of NS answer
    for rrset in results.response.answer:
        if rrset.rdtype == 2:
            for rrset_value in rrset.items:
                ns_hostname = str( rrset_value ).lower()
                # Add this to our NS_IP_MAP as an empty entry
                if not ns_hostname in NS_IP_MAP:
                    NS_IP_MAP[ ns_hostname ] = []

                ns_dict = {
                    "ns_hostname": ns_hostname,
                    "ttl": int( rrset.ttl ),
                    "hostname": str( rrset.name ).lower(),
                }

                # Since NS results sometimes won't have a glue record we will have to retrieve it..
                # First check out own DNS cache, if that fails then just use our resolver to get the IP.
                ns_ip = False

                if len( NS_IP_MAP[ ns_hostname ] ) == 0 :
                    NS_IP_MAP[ ns_hostname ] = get_hostname_ips( ns_hostname )

                if len( NS_IP_MAP[ ns_hostname ] ) > 0 :
                    ns_ip = NS_IP_MAP[ ns_hostname ][0]

                if ns_ip:
                    ns_dict[ "ns_ip" ] = ns_ip

                return_dict[ "answer_ns" ].append( ns_dict )

                # If this was an authoratative answer we need to save that for graphing.
                if is_authoratative( return_dict[ "flags" ] ) and not ( ns_hostname in AUTHORITATIVE_NS_LIST ):
                    AUTHORITATIVE_NS_LIST.append( ns_hostname )

    # TODO: DRY this up somehow ^^^

    return return_dict

def enumerate_nameservers( domain_name ):
    if not domain_name.endswith( "." ):
        domain_name += "."

    # First get a random root server and query it to bootstrap our walk of the chain.
    root_ns_set = get_random_root_ns_set()
    tld_ns_results = ns_query( domain_name, root_ns_set[ "ip" ], root_ns_set[ "hostname" ] )

    return _enumerate_nameservers( domain_name, tld_ns_results, 0, MAX_RECURSION_DEPTH )

def _enumerate_nameservers( domain_name, previous_ns_result, depth, max_depth ):
    # Take the previous DNS results and do DNS queries against all of the returned nameservers.

    # Start with NS returned in ADDITIONAL section of answer.
    for ns_rrset in previous_ns_result[ "additional_ns" ]:
        ns_results = ns_query( domain_name, ns_rrset[ "ns_ip" ], ns_rrset[ "ns_hostname" ] )

        if depth < max_depth:
            _enumerate_nameservers( domain_name, ns_results, ( depth + 1 ), max_depth )

    for ns_rrset in previous_ns_result[ "answer_ns" ]:
        if "ns_ip" in ns_rrset:
            ns_results = ns_query( domain_name, ns_rrset[ "ns_ip" ], ns_rrset[ "ns_hostname" ] )

            if depth < max_depth:
                _enumerate_nameservers( domain_name, ns_results, ( depth + 1 ), max_depth )

    for ns_rrset in previous_ns_result[ "authority_ns" ]:
        if "ns_ip" in ns_rrset:
            ns_results = ns_query( domain_name, ns_rrset[ "ns_ip" ], ns_rrset[ "ns_hostname" ] )

            if depth < max_depth:
                _enumerate_nameservers( domain_name, ns_results, ( depth + 1 ), max_depth )

def draw_graph_from_cache( target_hostname ):
    GRAPH_DATA = """
digraph G {
graph [ label=\"""" + target_hostname + """ DNS Trust Graph\", labelloc="t", pad="3", nodesep="1", ranksep="5", fontsize=50];
edge[arrowhead=vee, arrowtail=inv, arrowsize=.7]
concentrate=true;
"""
    for cache_key, ns_results in MASTER_DNS_CACHE.iteritems():
        print( "[ STATUS ] Building '" + cache_key + "'...")
        GRAPH_DATA += get_graph_data_for_ns_results( ns_results[ "authority_ns" ], ns_results )
        GRAPH_DATA += get_graph_data_for_ns_results( ns_results[ "additional_ns" ], ns_results )
        GRAPH_DATA += get_graph_data_for_ns_results( ns_results[ "answer_ns" ], ns_results )

    GRAPH_DATA += "\n}"
    return GRAPH_DATA

def get_graph_data_for_ns_results( ns_list, ns_results ):
    return_graph_data_string = ""

    for ns_rrset in ns_list:
        potential_edge = ns_results[ "nameserver_hostname" ] + "->" + ns_rrset[ "ns_hostname" ]

        if not potential_edge in PREVIOUS_EDGES:
            PREVIOUS_EDGES.append( potential_edge )
            return_graph_data_string += "\"" + ns_results[ "nameserver_hostname" ] + "\" -> \"" + ns_rrset[ "ns_hostname" ] + "\" [shape=ellipse]"

            return_graph_data_string += "[label=<<i>" + ns_results[ "hostname" ] + "?</i><br /><font point-size=\"10\">" + ns_results[ "rcode_string" ] + "</font>>] "

            if not "AA" in ns_results[ "flags" ]:
                return_graph_data_string += "[style=\"dashed\", color=\"#a3a3a3\"] "
            else:
                return_graph_data_string += "[color=\"#0099ff\"] "

            return_graph_data_string += ";\n"

    # Make all nameservers which were specified with an AA flag blue.
    for ns_hostname in AUTHORITATIVE_NS_LIST:
        return_graph_data_string += "\"" + ns_hostname + "\" [shape=ellipse, style=filled, fillcolor=\"#0099ff\"];\n"

    # Make all nameservers without any IP red because they might be vulnerable.
    for ns_hostname, ns_hostname_ip_list in NS_IP_MAP.iteritems():
        if len( ns_hostname_ip_list ) == 0:
            return_graph_data_string += "\"" + ns_hostname + "\" [shape=ellipse, style=filled, fillcolor=\"#ff0000\"];\n"

        base_domain = get_base_domain( ns_hostname )
        if GANDI_API_KEY != "" and is_domain_available( base_domain ):
            node_name = "Base domain '" + base_domain + "' unregisted!"
            potential_edge = ns_hostname + "->" + node_name
            if not potential_edge in PREVIOUS_EDGES:
                PREVIOUS_EDGES.append( potential_edge )
                return_graph_data_string += "\"" + ns_hostname + "\" -> \"" + node_name + "\";\n"
                return_graph_data_string += "\"" + node_name + "\"[shape=octagon, style=filled, fillcolor=\"#ff7700\"];\n"

    # Make nodes for DNS error states encountered like NXDOMAIN, Timeout, etc.
    for query_error in QUERY_ERROR_LIST:
        potential_edge = query_error[ "ns_hostname" ] + "->" + query_error[ "error" ]

        if not potential_edge in PREVIOUS_EDGES:
            PREVIOUS_EDGES.append( potential_edge )
            return_graph_data_string += "\"" + query_error[ "ns_hostname" ] + "\" -> \"" + query_error[ "error" ] + "\" "
            return_graph_data_string += "[label=<<i>" + query_error[ "hostname" ] + "?</i><br /><font point-size=\"10\">" + query_error[ "error" ] + "</font>>];\n"
            return_graph_data_string += "\"" + query_error[ "error" ] + "\" [shape=octagon, style=filled, fillcolor=\"#fff200\"];\n"

    return return_graph_data_string


def write_file( file_name, file_data ):
    file_handler = open( file_name, "w" )
    file_handler.write( file_data )
    file_handler.close()
    return

def read_file( file_name ):
    file_handler = open( file_name, "r" )
    contents = file_handler.read()
    file_handler.close()
    return contents

def get_hostname_ips( hostname ):
    return_ips = []
    try:
        answer = dns_query( hostname, "A", DEFAULT_RESOLVER )
        if answer.rrset:
            for rrset in answer.rrset:
                return_ips.append( str( rrset ) )
    except:
        return []

    return return_ips

def print_logo():
    print( """
  ______                __ ______
 /_  __/______  _______/ //_  __/_______  ___  _____
  / / / ___/ / / / ___/ __// / / ___/ _ \/ _ \/ ___/
 / / / /  / /_/ (__  ) /_ / / / /  /  __/  __(__  )
/_/ /_/   \__,_/____/\__//_/ /_/   \___/\___/____/
          Graphing & Scanning DNS Delegation Trees
""")

if __name__ == "__main__":
    parser = argparse.ArgumentParser( description="Graph out a domain's DNS delegation chain and trust trees!" )
    parser.add_argument( "-t", "--target", dest="target_hostname", help="Target hostname to generate delegation graph from.", required=True )
    parser.add_argument( "-o", "--open", dest="open", help="Open the generated graph once run.", action="store_true" )
    parser.add_argument( "-dc", "--domain-check", dest="domain_check", help="Check if nameserver base domains are expired. Specify a Gandi API key." )
    parser.add_argument( "-x", "--export-formats", dest="export_formats", help="Comma-seperated export formats, e.g: -x png,pdf" )
    args = parser.parse_args()

    print_logo()

    if args.domain_check:
        GANDI_API_KEY = args.domain_check

    target_hostname = args.target_hostname

    enumerate_nameservers( target_hostname )

    # Render graph image
    grapher = pgv.AGraph(
        draw_graph_from_cache( target_hostname )
    )

    output_graph_file = "./output/" + target_hostname + "_trust_tree_graph."

    export_formats = []
    if args.export_formats:
        export_parts = args.export_formats.split( "," )
        for part in export_parts:
            export_formats.append( part.strip() )
    else:
        export_formats.append( "png" )

    for export_format in export_formats:
        file_name = output_graph_file + export_format
        try:
            os.mkdir("output")
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        grapher.draw( file_name, prog="dot" )
        if args.open:
            print( "[ STATUS ] Opening final graph..." )
            subprocess_call( [ "open", file_name ])

    print( "[ SUCCESS ] Finished generating graph!" )
