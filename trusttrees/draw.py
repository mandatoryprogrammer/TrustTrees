import json
import platform
import subprocess

import boto3
import pygraphviz

from . import global_state
from .constants import (
    BLUE,
    GRAY,
    ORANGE,
    RED,
    YELLOW,
)
from .utils import (
    get_available_base_domains,
    get_nameservers_with_no_ip,
    is_authoritative,
)


PLATFORM_SYSTEM_TO_OPEN_COMMAND = {
    'darwin': 'open',
    'linux': 'xdg-open',
}


def _draw_graph_from_cache(target_hostname):
    """
    Iterates through MASTER_DNS_CACHE, and calls _get_graph_data_for_ns_result()

    :returns: string
    For pygraphviz.AGraph()
    """
    graph_data = (
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

    for cache_key, ns_result in global_state.MASTER_DNS_CACHE.items():
        print(f"[ STATUS ] Building '{cache_key}'...")
        for section_of_NS_answer in (
            'additional_ns',
            'authority_ns',
            'answer_ns',
        ):
            graph_data += _get_graph_data_for_ns_result(
                ns_list=ns_result[section_of_NS_answer],
                ns_result=ns_result,
            )

    graph_data += '\n}'
    return graph_data


def _get_graph_data_for_ns_result(ns_list, ns_result):
    return_graph_data_string = ''

    for ns_rrset in ns_list:
        potential_edge = (
            f"{ns_result['nameserver_hostname']}->{ns_rrset['ns_hostname']}"
        )

        if potential_edge not in global_state.PREVIOUS_EDGES:
            global_state.PREVIOUS_EDGES.add(potential_edge)
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
    for ns_hostname in global_state.AUTHORITATIVE_NS_LIST:
        return_graph_data_string += (
            f'"{ns_hostname}" [shape=ellipse, style=filled, fillcolor="{BLUE}"];\n'
        )

    # Make all nameservers without any IPs red because they are probably vulnerable
    for ns_hostname in get_nameservers_with_no_ip():
        return_graph_data_string += (
            f'"{ns_hostname}" [shape=ellipse, style=filled, fillcolor="{RED}"];\n'
        )

    # Make all nameservers with available base domains orange because they are probably vulnerable
    for base_domain, ns_hostname in get_available_base_domains():
        node_name = f"Base domain '{base_domain}' unregistered!"
        potential_edge = f'{ns_hostname}->{node_name}'
        if potential_edge not in global_state.PREVIOUS_EDGES:
            global_state.PREVIOUS_EDGES.add(potential_edge)
            return_graph_data_string += (
                f'"{ns_hostname}" -> "{node_name}";\n'
            )
            return_graph_data_string += (
                f'"{node_name}"[shape=octagon, style=filled, fillcolor="{ORANGE}"];\n'
            )

    # Make nodes for DNS error states encountered like NXDOMAIN, Timeout, etc.
    for query_error in global_state.QUERY_ERROR_LIST:
        potential_edge = (
            f'{query_error["ns_hostname"]}->{query_error["error"]}'
        )

        if potential_edge not in global_state.PREVIOUS_EDGES:
            global_state.PREVIOUS_EDGES.add(potential_edge)
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


def generate_graph(
    target_hostname,
    export_formats,
    only_draw_problematic,
    open_graph_file,
    upload_args,
):
    output_graph_file = f'./output/{target_hostname}_trust_tree_graph'

    graph_data = _draw_graph_from_cache(target_hostname)
    if (
        only_draw_problematic
        and
        ORANGE not in graph_data
        and
        RED not in graph_data
    ):
        print(f'[ STATUS ] {target_hostname} is not problematic, skipping!')
        return
    # Render graph image
    grapher = pygraphviz.AGraph(graph_data)

    for export_format in export_formats:
        filename = f'{output_graph_file}.{export_format}'
        grapher.draw(filename, prog='dot')
        if open_graph_file:
            print('[ STATUS ] Opening final graph...')
            subprocess.call(
                [
                    PLATFORM_SYSTEM_TO_OPEN_COMMAND[platform.system().lower()],
                    filename,
                ],
            )
        if upload_args:
            print('[ STATUS ] Uploading to AWS...')
            prefix, bucket = upload_args.split(',')
            with open(global_state.AWS_CREDS_FILE, 'r') as f:
                creds = json.load(f)
            client = boto3.client(
                's3',
                aws_access_key_id=creds['accessKeyId'],
                aws_secret_access_key=creds['secretAccessKey'],
                region_name='us-west-1',
            )
            client.upload_file(prefix+filename, bucket, filename)

    print('[ SUCCESS ] Finished generating graph!')
