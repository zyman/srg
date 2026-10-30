"""Scoped Resource Gateway control protocol: policy, adapters and durable plans.

Copyright (c) 2026 SRG contributors. MIT licensed; see LICENSE.
Adapters are trusted installed code, never caller-provided commands.
"""
import hashlib
import json
import re
import secrets
import sqlite3
import time


class Denied(ValueError):
    pass


class Conflict(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def exact(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise Denied("invalid request fields")


def validate_policy(policy, adapters):
    actions = policy.get("actions", {})
    if not isinstance(actions, dict):
        raise ValueError("actions must be an object")
    for name, action in actions.items():
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name):
            raise ValueError("invalid action name")
        if not isinstance(action, dict) or not isinstance(action.get("description"), str) or not 1 <= len(action["description"]) <= 300:
            raise ValueError("action description required")
        if not isinstance(action.get("operation"), str) or not action["operation"]:
            raise ValueError("action operation required")
        if not isinstance(action.get("targets"), list) or not action["targets"] or any(type(x) is not str or not 1 <= len(x) <= 128 for x in action["targets"]):
            raise ValueError("exact target list required")
        if action.get("adapter") not in adapters:
            raise ValueError("unknown action adapter")
        if action.get("risk") != "routine":
            raise ValueError("only routine actions can be installed")
        adapters[action["adapter"]].validate(action)
    for client, grants in policy.get("write_grants", {}).items():
        if client not in policy["clients"] or not isinstance(grants, list) or any(x not in actions for x in grants):
            raise ValueError("invalid write grants")


class Controller:
    """Serialized HTTP server plus durable claim-before-execute ledger.

    A crash after claiming a plan leaves it 'running': never automatically retry.
    This is at-most-one execution attempt per plan, not exactly-once delivery.
    """
    def __init__(self, policy, adapters, database, clock=time.time):
        validate_policy(policy, adapters)
        self.policy, self.adapters, self.clock = policy, adapters, clock
        self.revision = hashlib.sha256(canonical(policy).encode()).hexdigest()
        self.db = sqlite3.connect(database, check_same_thread=False)
        self.db.execute('CREATE TABLE IF NOT EXISTS plans (id TEXT PRIMARY KEY, client TEXT NOT NULL, revision TEXT NOT NULL, expires REAL NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, before_state TEXT NOT NULL, status TEXT NOT NULL, result TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, timestamp REAL NOT NULL, client TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL, previous TEXT NOT NULL, digest TEXT NOT NULL)')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.commit()

    def audit(self, client, event, detail):
        previous = self.db.execute('SELECT digest FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
        previous = previous[0] if previous else '0' * 64
        timestamp = self.clock()
        encoded = canonical(detail)
        digest = hashlib.sha256(canonical([timestamp, client, event, encoded, previous]).encode()).hexdigest()
        self.db.execute('INSERT INTO audit(timestamp,client,event,detail,previous,digest) VALUES(?,?,?,?,?,?)', (timestamp, client, event, encoded, previous, digest))
        self.db.commit()

    def audit_tail(self, client):
        rows = self.db.execute('SELECT seq,timestamp,event,detail,previous,digest FROM audit WHERE client=? ORDER BY seq DESC LIMIT 100', (client,)).fetchall()
        return [{"seq": r[0], "timestamp": r[1], "event": r[2], "detail": json.loads(r[3]), "previous": r[4], "digest": r[5]} for r in rows]

    def action(self, client, name, target):
        if name not in self.policy.get("write_grants", {}).get(client, []):
            raise Denied("action not granted")
        action = self.policy["actions"][name]
        if type(target) is not str or target not in action["targets"]:
            raise Denied("target not allowed")
        return action, self.adapters[action["adapter"]]

    def capabilities(self, client):
        return {"protocol": "srg/1", "policy_revision": self.revision, "actions": {
            name: {"description": self.policy["actions"][name]["description"],
                   "targets": self.policy["actions"][name]["targets"], "risk": "routine"}
            for name in self.policy.get("write_grants", {}).get(client, [])}}

    def plan(self, client, request):
        exact(request, ("action", "target"))
        if type(request["action"]) is not str:
            raise Denied("invalid action")
        try:
            action, adapter = self.action(client, request["action"], request["target"])
        except Denied:
            self.audit(client, "plan.denied", {"request_digest": hashlib.sha256(canonical(request).encode()).hexdigest()})
            raise
        plan_id, expires = secrets.token_hex(24), self.clock() + 120
        adapter.request_id = plan_id
        adapter.audit = lambda event, detail: self.audit(client, event, {"plan_id": plan_id, "action": request["action"], **detail})
        self.audit(client, "prepare.started", {"plan_id": plan_id, "action": request["action"], "target": request["target"]})
        before = adapter.prepare(action, request["target"])
        self.audit(client, "prepare.verified", {"plan_id": plan_id, "action": request["action"], "target": request["target"], "state_digest": hashlib.sha256(canonical(before).encode()).hexdigest()})
        # Keep an installation from accumulating unbounded expired previews.
        self.db.execute("DELETE FROM plans WHERE expires < ? AND status = 'planned'", (self.clock() - 86400,))
        self.db.execute("INSERT INTO plans VALUES (?,?,?,?,?,?,?,?,?)", (plan_id, client, self.revision, expires, request["action"], request["target"], canonical(before), "planned", None))
        self.db.commit()
        self.audit(client, "plan.created", {"plan_id": plan_id, "action": request["action"], "target": request["target"]})
        return {"plan_id": plan_id, "action": request["action"], "target": request["target"], "before": before, "expires": expires, "policy_revision": self.revision}

    def status(self, client, plan_id):
        row = self.db.execute("SELECT action,target,status,result FROM plans WHERE id=? AND client=?", (plan_id, client)).fetchone()
        if row is None:
            raise Denied("unknown plan")
        return {"plan_id": plan_id, "action": row[0], "target": row[1], "status": row[2], "result": json.loads(row[3]) if row[3] else None}

    def apply(self, client, request):
        exact(request, ("plan_id",))
        plan_id = request["plan_id"]
        if type(plan_id) is not str or not re.fullmatch(r"[a-f0-9]{48}", plan_id):
            raise Denied("invalid plan id")
        row = self.db.execute("SELECT revision,expires,action,target,before_state,status FROM plans WHERE id=? AND client=?", (plan_id, client)).fetchone()
        if row is None:
            raise Denied("unknown plan")
        if row[0] != self.revision or row[1] <= self.clock() or row[5] != "planned":
            self.audit(client, "apply.rejected", {"plan_id": plan_id, "status": row[5]})
            raise Conflict("plan expired, policy changed, or execution already claimed")
        action, adapter = self.action(client, row[2], row[3])
        adapter.request_id = plan_id
        adapter.audit = lambda event, detail: self.audit(client, event, {"plan_id": plan_id, **detail})
        self.audit(client, "apply.requested", {"plan_id": plan_id, "action": row[2], "target": row[3]})
        # Claim durably before all execution and verification. No automatic retries.
        changed = self.db.execute("UPDATE plans SET status='running' WHERE id=? AND status='planned'", (plan_id,)).rowcount
        self.db.commit()
        if changed != 1:
            raise Conflict("plan already claimed")
        try:
            before = json.loads(row[4])
            if adapter.prepare(action, row[3]) != before:
                raise Conflict("target changed since preview")
            self.audit(client, "execute.started", {"plan_id": plan_id, "action": row[2], "target": row[3]})
            adapter.audit = lambda event, detail: self.audit(client, event, {"plan_id": plan_id, **detail})
            result = adapter.execute(action, row[3], before)
            self.audit(client, "execute.verified", {"plan_id": plan_id, "result_digest": hashlib.sha256(canonical(result).encode()).hexdigest()})
            canonical(result)
        except Exception as error:
            status = "conflict" if isinstance(error, Conflict) else "uncertain"
            self.db.execute("UPDATE plans SET status=?,result=? WHERE id=?", (status, canonical({"error": "execution not completed or not verified; inspect target before making a new plan"}), plan_id))
            self.db.commit()
            self.audit(client, "execute." + status, {"plan_id": plan_id})
            raise
        self.db.execute("UPDATE plans SET status='succeeded',result=? WHERE id=?", (canonical(result), plan_id))
        self.db.commit()
        return self.status(client, plan_id)
