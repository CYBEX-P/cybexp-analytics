"""unittests for analytics.filters.email"""

import builtins
import pdb
from pprint import pprint
import unittest

from tahoe.tests.identity.test_backend import setUpBackend, tearDownBackend

if __name__ != 'analytics.tests.filters.test_email':
    import sys, os
    J = os.path.join
    sys.path = ['..', J('..','..'), J('..','..','..')] + sys.path
    del sys, os


from filters import set_filter_backend, Email


def make_test_data():
    with open('email.txt', 'r') as fp:
        builtins.email_str = fp.read()

    builtins.orgid = 'ABC123'
    builtins.timezone = 'US/Pacific'

def delete_test_data():
    del builtins.email_str, builtins.orgid, builtins.timezone


def setUpModule():
    builtins._backend = setUpBackend()
    set_filter_backend(_backend)
    

def tearDownModule():
    tearDownBackend(_backend)
    del builtins._backend


class EmailTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _backend.drop()
        make_test_data()

    @classmethod
    def tearDownClass(cls):
        delete_test_data()

    def test_01(self):
        e = Email()
        raw_ref = e.parse(email_str, orgid, timezone)
        e = _backend.find_one({'itype':'event'})


if __name__ == '__main__':
    unittest.main()
