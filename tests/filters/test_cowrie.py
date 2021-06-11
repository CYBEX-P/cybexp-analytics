"""unittests for analytics.filters.email"""

import builtins
import pdb
import json
from pprint import pprint
import unittest

from tahoe.tests.identity.test_backend import setUpBackend, tearDownBackend

if __name__ != 'analytics.tests.filters.test_cowrie':
    import sys, os
    J = os.path.join
    sys.path = ['..', J('..','..'), J('..','..','..')] + sys.path
    del sys, os

from filters import set_filter_backend, Cowrie


def make_test_data():
    with open('cowrie_raw.txt', 'r') as fp:
        builtins.data_str = fp.read()

    builtins.orgid = 'ABC123'
    builtins.timezone = 'US/Pacific'

def delete_test_data():
    del builtins.data_str, builtins.orgid, builtins.timezone


def setUpModule():
    builtins._backend = setUpBackend()
    set_filter_backend(_backend)
    

def tearDownModule():
    tearDownBackend(_backend)
    del builtins._backend


class CowireTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _backend.drop()
        make_test_data()

    @classmethod
    def tearDownClass(cls):
        delete_test_data()

    def test_01(self):
        lines = data_str.split('\n')
        c = Cowrie()
        for d in lines:
            if not d:
                continue
            m = json.loads(d)['data']['message']
            print(m)
            raw_ref = c.parse(m, orgid, timezone)
            if raw_ref == False:
                continue

            e = _backend.find_one({'itype':'event', '_hash':{'$in':raw_ref}})


if __name__ == '__main__':
    unittest.main()
