#!/usr/bin/env python3
"""Export the portable reference implementation, never site policy or secrets."""
import argparse
from pathlib import Path
import tarfile
import gzip
import hashlib
from version import __version__

FILES = ['gateway_client.py', 'mcp_server.py', 'requirements-mcp.txt', 'test_mcp.py',
         'test_gateway_client.py', 'MCP.md', 'examples/mcp-client.json', 'gateway.py', 'client.py', 'control.py', 'action_adapters.py', 'audit.py',
         'ssh_action.py', 'provision.py', 'test_gateway.py', 'test_control.py',
         'make-release.py', 'ledger.py', 'ssh_transport.py', 'version.py', 'requirements-dev.txt', 'pyproject.toml',
         'test_release.py', 'test_client.py', 'CHANGELOG.md', 'ROADMAP.md', 'README.md', 'SECURITY.md', 'INSTALL.md', 'SECURITY-REVIEW.md',
         'test_install.py', 'ci/smoke-install.sh', 'examples/resources.json', 'examples/ha-action.json', 'FRAMEWORK.md', 'srg.schema.json', 'gateway.schema.json', 'ci/check-schemas.py', 'PROTOCOL.md', 'CONTRIBUTING.md', 'LICENSE',
         'examples/policy.json', 'examples/remote-policy.json',
         'examples/client.json', 'examples/srg.service', 'reader.sh']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    output = Path(args.output)
    checksum = Path(str(output) + '.sha256')
    if checksum.exists():
        parser.error('checksum destination already exists')
    # No host ownership, source times, PAX metadata or gzip filename/time leaks.
    with output.open('xb') as destination:
        with gzip.GzipFile(filename='', fileobj=destination, mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for name in sorted(FILES):
                    source = root / name
                    if source.is_symlink() or not source.is_file():
                        raise ValueError('release source must be a regular file: ' + name)
                    info = tarfile.TarInfo('srg-' + __version__ + '/' + name)
                    info.size = source.stat().st_size
                    info.mode = 0o644
                    info.mtime = info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    with source.open('rb') as stream:
                        archive.addfile(info, stream)
    with checksum.open('x') as receipt:
        receipt.write(hashlib.sha256(output.read_bytes()).hexdigest() + '  ' + output.name + '\n')
    print(args.output)


if __name__ == '__main__':
    main()
