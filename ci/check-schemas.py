"""Development-only schema checks; the gateway has no jsonschema dependency."""
import copy
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from control import Controller  # noqa: E402
from test_control import FakeAdapter, CLIENT  # noqa: E402

schemas = [json.loads((ROOT / name).read_text()) for name in ('srg.schema.json', 'gateway.schema.json')]
for schema in schemas:
    Draft202012Validator.check_schema(schema)
registry = Registry().with_resources((schema['$id'], Resource.from_contents(schema)) for schema in schemas)

def validator(ref):
    return Draft202012Validator({'$ref': ref}, registry=registry, format_checker=FormatChecker())

config = validator('urn:srg:reference:config:1')
policy = json.loads((ROOT / 'examples/policy.json').read_text())
config.validate(policy)
policy['resources'].update(json.loads((ROOT / 'examples/resources.json').read_text()))
policy['actions'].update(json.loads((ROOT / 'examples/ha-action.json').read_text()))
config.validate(policy)
for mutate in (lambda p: p.update(port=0), lambda p: p.update(bind='::1'),
               lambda p: p['resources'].update(bad={'kind':'ssh','host':'-option','credential':'key'}),
               lambda p: p['resources'].update(bad={'kind':'https','url':'http://insecure'}),
               lambda p: p['resources'].update(bad={'kind':'unknown'})):
    bad=copy.deepcopy(policy);mutate(bad)
    assert list(config.iter_errors(bad)), 'invalid reference configuration accepted'
controller=Controller({'clients':[CLIENT], 'actions':{'restart':{'adapter':'fake','operation':'restart','description':'test','risk':'routine','targets':['app']}},'write_grants':{CLIENT:['restart']}}, {'fake':FakeAdapter()}, ':memory:')
try:
    plan=controller.plan(CLIENT,{'action':'restart','target':'app'})
    examples={'planRequest':{'action':'restart','target':'app'},'applyRequest':{'plan_id':plan['plan_id']},'planResponse':plan,'capabilitiesResponse':controller.capabilities(CLIENT),'planStatusResponse':controller.status(CLIENT,plan['plan_id']),'applyResponse':controller.apply(CLIENT,{'plan_id':plan['plan_id']})}
    for name, example in examples.items():
        check=validator('urn:srg:draft:1#/$defs/'+name)
        check.validate(example)
        assert list(check.iter_errors({**example,'unexpected':True})),name
finally:
    controller.db.close()
print('Schemas, backend examples, actual protocol responses and negative cases passed.')
