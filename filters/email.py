"""Parse raw email into Tahoe event."""

from email.parser import Parser
from email.policy import default

from .common import Filter, tahoe, Instance, Attribute, Object, Event

class Email(Filter):

    @property
    def filt_id(self):
        return "6e52bc6a-af7f-41ea-8684-e39c42d4aa3f"

    @property
    def raw_sub_type(self):
        return "email"

    def parse(self, data, orgid, timezone):
        data = data['data']
        e = Parser(policy=default).parsestr(data)

        for k in ['from', 'to', 'subject', 'date']:
            if not e[k]:
                return False

        # From
        # ----
        df = e['from']
        if df[-1] == '>':
            df = df.rpartition(' ')
            afn = df[0]
            afe = df[-1][1:-1]
        else:
            afn = None
            afe = df
        if afn:
            afn = Attribute('name', afn)
        afe = Attribute('email_addr', afe)

        # Sending IP
        # ----------
        asip = e['X-Mailgun-Sending-Ip']
        if asip:
            asip = Attribute('ipv4', asip)

        # Src Object
        # ----------
        dosrc = [a for a in [afn, afe, asip] if a]
        osrc = Object('src', dosrc)

        # Reply to
        # --------
        art = e['reply-to']
        if art:
            art = Attribute('email_addr', art)
            art = Object('reply_to', art)

        # To
        # --
        dt = e['to']
        if dt[-1] == '>':
            dt = dt.rpartition(' ')
            atn = dt[0]
            ate = dt[-1][1:-1]
        else:
            atn = None
            ate = dt
        if atn:
            atn = Attribute('name', atn)
        ate = Attribute('email_addr', ate)

        # Dst Object
        # ----------
        dodst = [a for a in [atn, ate] if a]
        odst = Object('dst', dodst)

        # Subject
        # -------
        asbj = Attribute('subject', e['subject'])

        
        # Body
        # ----
        simplest = e.get_body(preferencelist=('plain', 'html'))
        body = simplest.get_content()
        ab = Attribute('body', body)

        # Date
        # ----
        t = e['date'].datetime.timestamp()

        # Email Event
        # -----------
        event_data = [i for i in [osrc, art, odst, asbj, ab] if i]
      
        event = Event('email', event_data, orgid, t)

        raw_ref = event._ref + [event._hash]
        return raw_ref

        
        
