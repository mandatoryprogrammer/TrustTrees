import sys

from . import global_state
from .dns import enumerate_nameservers
from .draw import generate_graph
from .usage import parse_args
from .utils import (
    clear_global_state,
    create_output_dir,
    print_logo,
)


def main(command_line_args=sys.argv[1:]):
    args = parse_args(command_line_args)

    print_logo()
    create_output_dir()

    if args.aws_creds_filepath:
        global_state.AWS_CREDS_FILE = args.aws_creds_filepath
    elif args.gandi_api_v4_key:
        global_state.GANDI_API_V4_KEY = args.gandi_api_v4_key
    elif args.gandi_api_v5_key:
        global_state.GANDI_API_V5_KEY = args.gandi_api_v5_key
    else:
        global_state.CHECK_DOMAIN_AVAILABILITY = False

    if args.target_hostname:
        target_hostnames = [args.target_hostname]
    else:
        targets = open(args.target_hostnames_list)
        target_hostnames = [
            hostname
            for hostname in
            targets.read().split('\n')
        ][:-1]  # Skip the EOF newline

    export_formats = [
        extension.strip()
        for extension in
        args.export_formats.split(',')
    ]

    for target_hostname in target_hostnames:
        clear_global_state()
        enumerate_nameservers(target_hostname)
        if args.no_graphing:
            continue
        generate_graph(
            target_hostname,
            export_formats,
            args.only_draw_problematic,
            args.open,
        )

    return 0


if __name__ == '__main__':
    sys.exit(main())
