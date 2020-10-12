import argparse


def _add_mutually_exclusive_required_args(parser):
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
        help='Text file with a list of target hostnames.',
    )
    parser.add_argument(
        '-h',
        '--help',
        action='help',
        help=argparse.SUPPRESS
    )


def _add_optional_args(parser):
    optional_group = parser.add_argument_group(title='optional arguments')
    optional_group.add_argument(
        '-o',
        '--open',
        dest='open',
        help='Open the generated graph(s) once run.',
        action='store_true',
    )

    optional_group.add_argument(
        '--only-problematic',
        dest='only_draw_problematic',
        help='Open generate graphs that are likely to be vulnerable.',
        action='store_true',
    )
    optional_group.add_argument(
        '--no-graphing',
        dest='no_graphing',
        help='Do not generate any graphs.',
        action='store_true',
    )

    optional_group.add_argument(
        '-x',
        '--export-formats',
        dest='export_formats',
        help='Comma-separated export formats, e.g: -x png,pdf',
        default='png',
    )

    optional_group.add_argument(
        '-u',
        '--upload-graph',
        dest='upload_args',
        help='Comma-separated AWS args, e.g: -u graphs,mybucket',
        metavar='PREFIX,BUCKET',
    )

    optional_group.add_argument(
        '--resolvers',
        dest='resolvers',
        help='Text file containing DNS resolvers to use.',
        metavar='RESOLVERS_FILE',
    )

    optional_domain_checking_group = parser.add_argument_group(
        title='optional arguments for domain-checking',
    )
    optional_domain_checking_group.add_argument(
        '--aws-credentials',
        dest='aws_creds_filepath',
        help='AWS credentials JSON file for checking if nameserver base domains are registerable.',
        metavar='AWS_CREDS_FILE',
    )
    optional_domain_checking_group.add_argument(
        '--gandi-api-v4-key',
        dest='gandi_api_v4_key',
        help='Gandi API V4 key for checking if nameserver base domains are registerable.',
        metavar='GANDI_API_V4_KEY',
    )
    optional_domain_checking_group.add_argument(
        '--gandi-api-v5-key',
        dest='gandi_api_v5_key',
        help='Gandi API V5 key for checking if nameserver base domains are registerable.',
        metavar='GANDI_API_V5_KEY',
    )
    optional_domain_checking_group.add_argument(
        '--dnsimple-api-v2-token',
        dest='dnsimple_api_v2_token',
        help='dnsimple API V2 access token for checking if nameserver base domains are registerable.',
        metavar='DNSIMPLE_ACCESS_TOKEN',
    )


def parse_args(args):
    if not args:
        args.append('-h')

    parser = argparse.ArgumentParser(
        description="Graph out a domain's DNS delegation chain and trust trees!",
        prog='trusttrees',
        add_help=False
    )

    _add_mutually_exclusive_required_args(parser)
    # `add_mutually_exclusive_group` does not accept a title, so change it
    parser._action_groups[1].title = 'mutually exclusive required arguments'

    _add_optional_args(parser)

    return parser.parse_args()
