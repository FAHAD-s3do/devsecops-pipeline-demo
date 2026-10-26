import copy
import unittest
from auditor import audit, render


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.container = dict(Name='demo', Config={'User':'1000:1000'}, HostConfig=dict(Privileged=False, NetworkMode='bridge', ReadonlyRootfs=True, Memory=1000000, PidsLimit=64), Mounts=[])

    def test_explicit_configuration(self):
        self.assertEqual(audit([self.container])['findings'], [])

    def test_risky_flags(self):
        self.container['HostConfig'].update(Privileged=True, NetworkMode='host', PidMode='host')
        self.assertEqual({f['rule'] for f in audit([self.container])['findings']}, {'PRIVILEGED','HOST_NETWORK','HOST_PID'})

    def test_root_variants(self):
        for user in ('', 'root', '0', '0:1000', 'root:group'):
            self.container['Config']['User'] = user
            self.assertIn('ROOT_USER_REVIEW', {f['rule'] for f in audit([self.container])['findings']})

    def test_limits_and_rootfs(self):
        self.container['HostConfig'].update(Memory=0, PidsLimit=-1, ReadonlyRootfs=False)
        self.assertEqual(len(audit([self.container])['findings']), 3)

    def test_socket_readonly_still_reported(self):
        self.container['Mounts'] = [dict(Source='/var/run/docker.sock', Destination='/socket', RW=False)]
        self.assertEqual(audit([self.container])['findings'][0]['rule'], 'DOCKER_SOCKET')

    def test_malformed_shapes(self):
        for data in ({}, [None], [{}]):
            with self.assertRaises(ValueError): audit(data)

    def test_report_escapes_name_and_omits_secrets(self):
        self.container['Name'] = '<script>alert(1)</script>'
        self.container['Config'].update(User='root', Env=['SECRET=private-value'])
        report = audit([self.container])
        output = render(report)
        self.assertNotIn('<script>', output)
        self.assertIn('&lt;script&gt;', output)
        self.assertNotIn('private-value', str(report))

    def test_invalid_limit(self):
        self.container['HostConfig']['Memory'] = 'unlimited'
        with self.assertRaises(ValueError): audit([self.container])
