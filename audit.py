#!/usr/bin/env python3
"""Verify or export an SRG audit ledger. Run on the gateway as its operator."""
import argparse
import hashlib
import json
import sqlite3
from pathlib import Path
from control import canonical


def verify(database):
    previous, count = '0' * 64, 0
    for seq, timestamp, client, event, detail, parent, digest in database.execute('SELECT seq,timestamp,client,event,detail,previous,digest FROM audit ORDER BY seq'):
        count += 1
        if seq != count or parent != previous or hashlib.sha256(canonical([timestamp, client, event, detail, parent]).encode()).hexdigest() != digest:
            raise ValueError('audit chain mismatch at sequence ' + str(seq))
        previous = digest
    return {'records': count, 'head': previous}


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
