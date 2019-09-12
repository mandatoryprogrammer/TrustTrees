import argparse


def _add_required_args(parser):
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


def _add_optional_args(parser):
    optional_group = parser.add_argument_group(title='optional arguments')
    optional_group.add_argument(
        '-o',
        '--open',
        dest='open',
        help='Open the generated graph once run.',
        action='store_true',
    )

    optional_group.add_argument(
        '--aws-credentials',
        dest='aws_creds_filepath',
        help='AWS credentials JSON file for checking if nameserver base domains are registerable.',
        metavar='AWS_CREDS_FILE',
    )
    optional_group.add_argument(
        '--gandi-api-v4-key',
        dest='gandi_api_v4_key',
        help='Gandi API V4 key for checking if nameserver base domains are registerable.',
        metavar='GANDI_API_V4_KEY',
    )
    optional_group.add_argument(
        '--gandi-api-v5-key',
        dest='gandi_api_v5_key',
        help='Gandi API V5 key for checking if nameserver base domains are registerable.',
        metavar='GANDI_API_V5_KEY',
    )

    optional_group.add_argument(
        '-x',
        '--export-formats',
        dest='export_formats',
        help='Comma-seperated export formats, e.g: -x png,pdf',
        default='png',
    )


def parse_args(args):
    if len(args) == 0:
        args.append('-h')

    parser = argparse.ArgumentParser(
        description="Graph out a domain's DNS delegation chain and trust trees!",
        prog='trusttrees',
    )

    """
    This hackery is due to `argparse` allowing only positional args to be required
    Named arguments are more descriptive
    """
    # Remove --help from the mutually exclusive required arguments group
    parser._action_groups[1]._group_actions = []
    _add_required_args(parser)
    # `add_mutually_exclusive_group` does not accept a title, so change it
    parser._action_groups[1].title = 'mutually exclusive required arguments'

    _add_optional_args(parser)

    return parser.parse_args()
