"""Parse Phishtank Feed into Tahoe events."""

from datetime import datetime as dt
import json
import logging
import time

from .sighting import Sighting

class PhishTankFeed(Sighting):

    @property
    def filt_id(self):
        return "e8f53cdc-1a9a-478d-ac4f-ab6a2f7e2341"

    @property
    def raw_sub_type(self):
        return "phishtank_feed"

    def parse(self, data, orgid, timezone):
        if isinstance(data, str):
            data = json.loads(data)

        data = data['data']
        data = data.split('\n')

        raw_ref = []
        for url in data:
            url = url.strip()
            if not url:
                continue
            d = {'url': url}
            r = super().parse(d, orgid, timezone,
                              category='malicious', context='malicious')
            raw_ref = raw_ref + r

        return raw_ref
        
