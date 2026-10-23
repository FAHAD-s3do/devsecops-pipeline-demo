import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from security_gate import inspect_source


class ShellValueTests(unittest.TestCase):
    def test_truthy_constants_enable_shell(self):
        for value in ('True', '1', '2', '0.5', '"enabled"', 'b"enabled"'):
            for call in ('run', 'Popen', 'call', 'check_call', 'check_output'):
                with self.subTest(value=value, call=call):
                    source = f'subprocess.{call}(command, shell={value})'
                    self.assertEqual(inspect_source(source), [{'rule': 'SHELL_TRUE', 'line': 1}])

    def test_false_constants_do_not_enable_shell(self):
        for value in ('False', '0', '0.0', '""', 'b""', 'None'):
            with self.subTest(value=value):
                self.assertEqual(inspect_source(f'subprocess.run(command, shell={value})'), [])

    def test_dynamic_values_remain_outside_analysis(self):
        self.assertEqual(inspect_source('subprocess.run(command, shell=setting)'), [])

    def test_constant_strings_and_comments_are_not_calls(self):
        self.assertEqual(inspect_source('# subprocess.run(command, shell=1)\ntext = "shell=1"'), [])

    def test_cli_blocks_truthy_constant_without_executing_source(self):
        script = Path(__file__).resolve().parents[1] / 'security_gate.py'
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'sample.py'
            source.write_text('raise RuntimeError("must not execute")\nsubprocess.run(command, shell=1)\n')
            result = subprocess.run([sys.executable, str(script), str(source)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['findings'], [{'file': str(source), 'rule': 'SHELL_TRUE', 'line': 2}])
            self.assertEqual(result.stderr, '')
