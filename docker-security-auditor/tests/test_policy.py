import unittest
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from policy import extra_checks
from auditor import audit


class PolicyTests(unittest.TestCase):
    def test_cli_threshold_and_json_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'fixture.json'
            path.write_text(json.dumps([{'Name':'test','Config':{'User':'1000'},'HostConfig':{'Memory':10,'PidsLimit':10,'ReadonlyRootfs':False},'Mounts':[]}]))
            script = str(Path(__file__).resolve().parents[1]/'auditor.py')
            for level, code in (('high',0),('low',1)):
                result = subprocess.run([sys.executable,script,'--fixture',str(path),'--fail-on',level],capture_output=True,text=True)
                self.assertEqual(result.returncode,code,result.stderr)
                self.assertEqual(json.loads(result.stdout)['summary']['low'],1)

    def test_capability_variants(self):
        for cap in ('SYS_ADMIN','CAP_SYS_ADMIN','ALL','sys_ptrace'):
            self.assertEqual(extra_checks({}, {'CapAdd':[cap]}, [])[0]['severity'], 'high')

    def test_narrow_capability_not_flagged(self):
        self.assertEqual(extra_checks({}, {'CapAdd':['NET_BIND_SERVICE']}, []), [])

    def test_security_option_separators(self):
        for opt in ('seccomp=unconfined','apparmor:unconfined','label=disable'):
            self.assertEqual(extra_checks({}, {'SecurityOpt':[opt]}, [])[0]['rule'], 'SECURITY_PROFILE_DISABLED')

    def test_sensitive_bind_boundaries(self):
        for path, expected in (('/etc/passwd',True),('/etc-backup',False),('/',True),('/srv/app',False)):
            self.assertEqual(bool(extra_checks({}, {}, [{'Type':'bind','Source':path}])), expected)

    def test_secret_values_never_exposed(self):
        report = extra_checks({'Env':['API_TOKEN=super-sensitive-value']}, {}, [])
        self.assertEqual(report[0]['rule'],'SECRET_ENV_REVIEW')
        self.assertNotIn('super-sensitive-value',str(report))
        self.assertNotIn('API_TOKEN',str(report))

    def test_malformed_options_rejected(self):
        for host in ({'SecurityOpt':'unconfined'},{'CapAdd':[None]},{'Devices':{}}):
            with self.assertRaises(ValueError): extra_checks({},host,[])

    def test_devices(self):
        self.assertEqual(extra_checks({}, {'Devices':[{}]}, [])[0]['rule'],'HOST_DEVICE_ACCESS')

    def test_summary_counts(self):
        r = audit([{'Name':'test','Config':{'User':'1000'},'HostConfig':{'Privileged':True,'Memory':10,'PidsLimit':10,'ReadonlyRootfs':True},'Mounts':[]}])
        self.assertEqual(r['summary']['critical'],1)
        self.assertEqual(sum(r['summary'].values()),len(r['findings']))
