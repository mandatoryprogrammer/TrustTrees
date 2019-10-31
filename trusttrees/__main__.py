import sys

from .dns import enumerate_nameservers
from .draw import generate_graph
from .usage import parse_args
from .utils import (
    clear_global_state,
    create_output_dir,
    print_logo,
    set_global_state_with_args,
)


def main(command_line_args=sys.argv[1:]):
    args = parse_args(command_line_args)

    print_logo()
    create_output_dir()
    set_global_state_with_args(args)

    if args.target_hostname:
        target_hostnames = [args.target_hostname]
    else:
        with open(args.target_hostnames_list) as targets:
            target_hostnames = targets.read().splitlines()

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
            args.upload_args,
        )

    return 0


if __name__ == '__main__':
    sys.exit(main())
