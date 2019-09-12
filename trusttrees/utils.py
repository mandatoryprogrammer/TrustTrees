import errno
import os


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
