"""Trusted independent checks; this file is outside the model's edit scope."""
import argparse
import json
import unittest
from application import app

parser = argparse.ArgumentParser()
parser.add_argument('--require-nosniff', action='store_true')
args = parser.parse_args()


class Contract(unittest.TestCase):
    def test_existing_routes(self):
        for path, status in [('/', 'ok'), ('/health', 'healthy')]:
            response = app.test_client().get(path)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json, {'status': status})

    def test_header_contract(self):
        if not args.require_nosniff:
            return
        client = app.test_client()
        for path in ['/', '/health', '/absent']:
            response = client.get(path)
            self.assertEqual(response.headers.get('X-Content-Type-Options'), 'nosniff')
        response = client.get('/')
        print(json.dumps({'status': response.status_code,
                          'headers': {'x-content-type-options': response.headers.get('X-Content-Type-Options')}}))


if not unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Contract)).wasSuccessful():
    raise SystemExit(1)
