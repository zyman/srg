#!/usr/bin/env python3
"""Export the portable reference implementation, never site policy or secrets."""
import argparse
from pathlib import Path
import tarfile

FILES = ['gateway.py', 'client.py', 'control.py', 'action_adapters.py', 'audit.py',
         'ssh_action.py', 'provision.py', 'test_gateway.py', 'test_control.py',
         'make-release.py', 'README.md', 'SECURITY.md', 'FRAMEWORK.md', 'srg.schema.json', 'PROTOCOL.md', 'CONTRIBUTING.md', 'LICENSE',
         'examples/policy.json', 'examples/remote-policy.json',
         'examples/client.json', 'examples/srg.service', 'examples/github-workflow.yml']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    with tarfile.open(args.output, 'x:gz') as archive:
        for name in FILES:
            archive.add(root / name, arcname='srg-0.1/' + name, recursive=False)
        # The existing reader-boundary test expects this relative fixture.
        reader = root / 'reader.sh'
        if not reader.exists():
            reader = root.parents[1] / 'ansible/roles/access_reader/files/reader.sh'
        archive.add(reader, arcname='srg-0.1/reader.sh', recursive=False)
    print(args.output)


if __name__ == '__main__':
    main()
