import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from security_gate import inspect_source


class EncodingTests(unittest.TestCase):
    def test_declared_encoding_finding(self):
        source=b'# coding: latin-1\n# caf\xe9\neval(data)\n'
        self.assertEqual(inspect_source(source),[dict(rule='DYNAMIC_EXECUTION',line=3)])

    def test_utf8_bom(self):
        self.assertEqual(inspect_source(b'\xef\xbb\xbfeval(data)\n'),[dict(rule='DYNAMIC_EXECUTION',line=1)])

    def test_invalid_encoding_rejected(self):
        for source in (b'# coding: nonexistent-codec\nx=1\n',b'# coding: ascii\n# \xff\n'):
            with self.subTest(source=source), self.assertRaises((SyntaxError,UnicodeError)):
                inspect_source(source)

    def test_cli_encoded_hash_and_exit_codes(self):
        script=Path(__file__).resolve().parents[1]/'security_gate.py'
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'sample.py'
            def run():
                return subprocess.run([sys.executable,str(script),str(path)],capture_output=True,text=True)
            safe=b'# coding: latin-1\nlabel="caf\xe9"\n'
            path.write_bytes(safe)
            clean=run()
            self.assertEqual(clean.returncode,0,clean.stderr)
            report=json.loads(clean.stdout)
            self.assertEqual(report['artifacts'][0]['sha256'],hashlib.sha256(safe).hexdigest())
            self.assertEqual(report['findings'],[])
            path.write_bytes(safe+b'eval(label)\n')
            flagged=run()
            self.assertEqual(flagged.returncode,1,flagged.stderr)
            self.assertEqual(json.loads(flagged.stdout)['findings'][0]['line'],3)
            path.write_bytes(b'# coding: unknown-codec\nx=1\n')
            invalid=run()
            self.assertEqual(invalid.returncode,2)
            self.assertEqual(invalid.stdout,'')
            self.assertNotIn('Traceback',invalid.stderr)
