import http.client
from http.server import HTTPServer
import threading
import unittest
from app import Handler
from security_gate import inspect_source
class Tests(unittest.TestCase):
 def test_eval_gate(self):self.assertEqual(inspect_source('eval(data)')[0]['rule'],'DYNAMIC_EXECUTION')
 def test_shell_gate(self):self.assertEqual(inspect_source('subprocess.run(cmd, shell=True)')[0]['rule'],'SHELL_TRUE')
 def test_safe_run(self):self.assertEqual(inspect_source('subprocess.run(["echo", "hello"], shell=False)'),[])
 def test_syntax_error(self):
  with self.assertRaises(SyntaxError):inspect_source('def bad(')
 def test_health_endpoint(self):
  server=HTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
  try:
   c=http.client.HTTPConnection('127.0.0.1',server.server_port);c.request('GET','/health');r=c.getresponse();self.assertEqual(r.status,200);self.assertEqual(r.getheader('X-Content-Type-Options'),'nosniff');r.read();c.close()
   c=http.client.HTTPConnection('127.0.0.1',server.server_port);c.request('GET','/missing');r=c.getresponse();self.assertEqual(r.status,404);r.read();c.close()
  finally:server.shutdown();thread.join();server.server_close()
