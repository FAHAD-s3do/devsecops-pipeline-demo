import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from auditor import audit


class InputContractTests(unittest.TestCase):
    def container(self, **host):
        return dict(Config={'User':'1000'}, HostConfig=host, Mounts=[])

    def test_booleans_reject_coercible_values(self):
        for key in ('Privileged','ReadonlyRootfs'):
            for value in (1, 0, 'true', 'false', None, [], {}):
                with self.subTest(key=key,value=value), self.assertRaises(ValueError):
                    audit([self.container(**{key:value})])

    def test_namespace_modes_require_strings(self):
        for key in ('NetworkMode','PidMode'):
            for value in (None, True, 1, [], {}):
                with self.subTest(key=key,value=value), self.assertRaises(ValueError):
                    audit([self.container(**{key:value})])

    def test_empty_collection_rejected(self):
        with self.assertRaises(ValueError): audit([])

    def test_actual_boolean_privileged_still_detected(self):
        report=audit([self.container(Privileged=True,ReadonlyRootfs=True)])
        self.assertEqual(report['summary']['critical'],1)

    def test_cli_bad_types_produce_no_report(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture=Path(directory)/'inspect.json'
            fixture.write_text(json.dumps([self.container(Privileged=1)]))
            result=subprocess.run([sys.executable,str(Path(__file__).resolve().parents[1]/'auditor.py'),'--fixture',str(fixture),'--fail-on','critical'],capture_output=True,text=True)
            self.assertEqual(result.returncode,2)
            self.assertEqual(result.stdout,'')
            self.assertIn('must be a boolean',result.stderr)
            self.assertNotIn('Traceback',result.stderr)
