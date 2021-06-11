"""Parse Cowrie Honeypot events into Tahoe events."""

from datetime import datetime as dt
import json
import logging
import time

from .common import Filter, tahoe, Attribute, Object, Event

class Sighting(Filter):

    @property
    def filt_id(self):
        return "05e66bff-c3e1-49a0-bd2e-ad203a1f94fc"

    @property
    def raw_sub_type(self):
        return "sighting"

    def parse(self, data, orgid, timezone,
              category='unknown', context='unknown'):
        if isinstance(data, str):
            data = json.loads(data)

        try:
            timestamp = data.pop('timestamp')
        except KeyError:
            timestamp = time.time()

        raw_ref = []
        for sub_type, value in data.items():

            att = Attribute(sub_type, value)

            mal_data = []
            ben_data = []
            if context=='malicious':
                mal_data.append(att)
            elif context=='benign':
                ben_data.append(att)
            
            event = Event('sighting', [att], orgid, timestamp,
                          mal_data=mal_data, ben_data=ben_data)

            event.set_category(category)
            
            raw_ref = raw_ref + event._ref + [event._hash]

        return raw_ref
        
