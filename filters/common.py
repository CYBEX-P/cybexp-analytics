import logging

import tahoe
from tahoe import Instance, Attribute, Object, Event, Session

from errors import BackendNotSetError

def set_filter_backend(analytics_backend):
    Filter._backend = analytics_backend
    Instance._backend = analytics_backend

_P = {"_id":0}

class Filter():
    _backend = None

    @property
    def filt_id(self):
        return NotImplemented

    def parse(self, data, orgid, timezone):
        return NotImplemented

    @property
    def raw_sub_type(self):
        return NotImplemented

    def run(self):
        if self._backend is None:
            raise BackendNotSetError("Set Filter._backend!")

        try:
            q = {'itype': 'raw', 'sub_type': self.raw_sub_type,
                 'filters': {'$ne': self.filt_id}, '_valid': {'$ne': False}}
            r = self._backend.find(q, _P, limit=1000, no_cursor_timeout=True)

            any_success = False
            for i in r:
                R = tahoe.parse(i, self._backend, validate=False)

                raw_ref = self.parse(R.data, R.orgid, R.timezone)
                
                q = {'_hash': R._hash}
                if raw_ref:
                    u = {"$addToSet": {"filters": self.filt_id}}
                    self._backend.update_one(q, u)
                    R.add_ref(raw_ref)
                    any_success = True
                else:
                    u ={"$set" : {"_valid" : False}}
                    self._backend.update_one(q, u)

            return any_success

        except (KeyboardInterrupt, SystemExit):
            raise
        
        except:
             logging.error(f"Error in {type(self)}.run!", exc_info=True)
             return False
