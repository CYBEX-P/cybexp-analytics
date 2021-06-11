"""Parse Cowrie Honeypot events into Tahoe events."""

from datetime import datetime as dt
import json
import logging
import time

from .sighting import Sighting

class OpenPhishFeed(Sighting):

    @property
    def filt_id(self):
        return "c4cd1ecf-1149-46e0-9daa-e2477016d8dc"

    @property
    def raw_sub_type(self):
        return "openphish_feed"

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
        
