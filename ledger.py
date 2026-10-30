"""Canonical ledger encoding and verification, shared without import cycles."""
import hashlib
import json


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def verify(database):
    previous, count = '0' * 64, 0
    for seq, timestamp, client, event, detail, parent, digest in database.execute('SELECT seq,timestamp,client,event,detail,previous,digest FROM audit ORDER BY seq'):
        count += 1
        if seq != count or parent != previous or hashlib.sha256(canonical([timestamp, client, event, detail, parent]).encode()).hexdigest() != digest:
            raise ValueError('audit chain mismatch at sequence ' + str(seq))
        previous = digest
    return {'records': count, 'head': previous}
