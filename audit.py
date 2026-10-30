#!/usr/bin/env python3
"""Verify or export an SRG audit ledger. Run on the gateway as its operator."""
import argparse
import json
import sqlite3
from pathlib import Path
from ledger import verify


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--database', required=True)
    parser.add_argument('--export', action='store_true')
    parser.add_argument('--backup', help='Create a consistent SQLite backup at a new path')
    args = parser.parse_args()
    database = sqlite3.connect(Path(args.database).resolve().as_uri() + '?mode=ro', uri=True)
    result = verify(database)
    if args.backup:
        import os
        fd = os.open(args.backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        destination = sqlite3.connect(args.backup)
        database.backup(destination)
        destination.close()
    if args.export:
        for row in database.execute('SELECT seq,timestamp,client,event,detail,previous,digest FROM audit ORDER BY seq'):
            print(json.dumps(dict(zip(('seq','timestamp','client','event','detail','previous','digest'), row))))
    else:
        print(json.dumps(result))
    database.close()


if __name__ == '__main__':
    main()
