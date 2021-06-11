"""Parse Cowrie Honeypot events into Tahoe events."""

from datetime import datetime as dt
import json
import logging

from .common import Filter, tahoe, Instance, Attribute, Object, Event, Session

class Cowrie(Filter):

    @property
    def filt_id(self):
        return "d2076b75-715e-4e4d-ae0a-a291cc6d90b7"

    @property
    def raw_sub_type(self):
        return "cowrie"

    def parse(self, data, orgid, timezone):
        if isinstance(data, str):
            data = json.loads(data)

        if 'eventid' not in data:
            return False

        eventid = data['eventid']

        timestamp = data['timestamp']
        timestamp = timestamp.replace("Z", "+00:00")
        timestamp = dt.fromisoformat(timestamp).timestamp()

        sub_type = None

        if eventid == "cowrie.client.fingerprint":
            pass
        elif eventid == "cowrie.client.kex":
            pass  
        elif eventid == "cowrie.client.size":
            pass
        elif eventid == "cowrie.client.var":
            pass
        elif eventid == "cowrie.client.version":
            pass
        elif eventid == "cowrie.command.failed":
            sub_type = 'shell_command'
            event_data, mal_data = command_failed(data)
        elif eventid == "cowrie.command.input":
            sub_type = 'shell_command'
            event_data, mal_data = command_input(data)
        elif eventid == "cowrie.command.success":
            sub_type = 'shell_command'
            event_data, mal_data = command_success(data)
        elif eventid == "cowrie.direct-tcpip.data":
            sub_type = 'network_traffic'
            event_data, mal_data = direct_tcp_ip_data(data)
        elif eventid == "cowrie.direct-tcpip.request":
            sub_type = 'network_traffic'
            event_data, mal_data = direct_tcp_ip_request(data)
        elif eventid == "cowrie.log.open":
            pass
        elif eventid == "cowrie.log.closed":
            pass
        elif eventid == "cowrie.login.failed":
            sub_type = 'login'
            event_data, mal_data = login_failed(data)
        elif eventid == "cowrie.login.success":
            sub_type = 'login'
            event_data, mal_data = login_success(data)
        elif eventid == "cowrie.session.closed":
            session_closed(data)
        elif eventid == "cowrie.session.connect":
            session_connect(data)
        elif eventid == "cowrie.session.file_download":
            sub_type = 'file_download'
            event_data, mal_data = session_file_download(data)
        elif eventid == "cowrie.session.file_download.failed":
            sub_type = 'file_download'
            event_data, mal_data = session_file_download_failed(data)
        elif eventid == "cowrie.session.file_upload":
            sub_type = 'file_upload'
            event_data, mal_data = session_file_upload(data)
        else:
            logging.warning(f"Unknown cowrie eventid={eventid}!")

        session = get_session(data)
        
        if sub_type is None:
            return [session._hash]

        attacker_ip_att = Attribute('ipv4', data["src_ip"])
        attacker_obj = Object('attacker', [attacker_ip_att])

        event_data = event_data + [attacker_obj]
        mal_data = mal_data + [attacker_ip_att, attacker_obj]

        event = Event(sub_type, event_data, orgid, timestamp,
                      mal_data=mal_data)
        event.set_category('malicious')

        session.add_event(event)

        raw_ref = event._ref + [event._hash, session._hash]

        return raw_ref
        


def command_input(data, success=None):
    command_att = Attribute('shell_command', data["input"])
    event_data = [command_att]
    if success is not None:
        success_att = Attribute('success', success)
        event_data.append(success_att)
    mal_data = [command_att]
    return event_data, mal_data


def command_success(data):
    return command_input(data, True)


def command_failed(data):
    return command_input(data, False)


def direct_tcp_ip(data, event_data=[]):    
    url_att = Attribute('url', data["dst_ip"])
    dport_att = Attribute('port', data["dst_port"])
    dst_obj = Object('dst', [url_att, dport_att])

    protocol_att = Attribute("protocol", "TCP")

    event_data += [dst_obj, protocol_att]
    mal_data = []
    return event_data, mal_data


def direct_tcp_ip_data(data):
    data_att = Attribute('data', data["data"])
    event_data = [data_att]
    return direct_tcp_ip(data, event_data=event_data)


def direct_tcp_ip_request(data):
    return direct_tcp_ip(data)


def login(data, success):
    username_att = Attribute('username', data["username"])
    password_att = Attribute('password', data["password"])
    cred_obj = Object('credential', [username_att, password_att])

    success_att = Attribute('success', success)

    method_att = Attribute('method', 'ssh')

    event_data = [cred_obj, success_att, method_att]
    mal_data = [cred_obj]
    return event_data, mal_data

def login_failed(data):
    return login(data, False)    


def login_success(data):
    return login(data, True)
    

def get_session(data):
    sessionid = data['session']
    sessionid_att = Attribute('sessionid', sessionid)
    sensor = data['sensor']
    sensor_att = Attribute('sesnor', sensor)
    session = Session('cowrie_session', [sessionid_att, sensor_att])
    return session


def get_session_timestamp(data):
    session = get_session(data)
    timestamp = data["timestamp"]
    timestamp = timestamp.replace("Z", "+00:00")
    timestamp = dt.fromisoformat(timestamp).timestamp()
    return session, timestamp
    

def session_closed(data):
    session, end_time = get_session_timestamp(data)
    duration = data['duration']
    update = {"duration": duration, "end_time": end_time}
    session._update(update)
    

def session_connect(data):
    session, start_time = get_session_timestamp(data)
    update = {"start_time" : start_time}
    session._update(update)


def get_url_filename(data):
    url = data['url'].strip()
    url_att = Attribute('url', url)
    filename = url.split('/')[-1].strip()
    filename_att = Attribute('filename', filename)
    return url_att, filename_att


def session_file_download(data):
    url_att, filename_att = get_url_filename(data)
    success_att = Attribute('success', True)
    sha256 = data['shasum']
    sha256_att = Attribute('sha256', sha256)
    file_obj = Object('file', [filename_att, sha256_att])
        
    event_data = [url_att, file_obj, success_att,]
    mal_data = [url_att, filename_att, sha256_att, file_obj]
    return event_data, mal_data
        

def session_file_download_failed(data):
    url_att, filename_att = get_url_filename(data)
    success_att = Attribute('success', False)
    file_obj = Object('file', [filename_att])
        
    event_data = [url_att, file_obj, success_att]
    mal_data = [url_att, filename_att, file_obj]
    return event_data, mal_data


def session_file_upload(data):
    filename = data['filename']
    filename_att = Attribute('filename', filename)
    sha256 = data['shasum']
    sha256_att = Attribute('sha256', sha256)
    file_obj = Object('file', [filename_att, sha256_att])

    event_data = [file_obj]
    mal_data = [filename_att, sha256_att, file_obj]
    
    message = data['message']
    if message[:4] == 'SFTP':
        method_att = Attribute('method', 'SFTP')
        outfile_att = Attribute('output_file_path', data['outfile'])

        event_data = event_data + [method_att, outfile_att]
    
    return event_data, mal_data











##class ClientKex(Cowrie):
##    def __init__(self, data):
##        self.event_type = 'ssh'
##        self.data, self.data = data.pop("data"), data
##
##        encCS = [e.split('@')[0] for e in self.data["encCS"]]
##        enc_algo = [Attribute('encr_algo', enc_algo) for enc_algo in encCS]
##
##        compCS = self.data["compCS"]
##        if compCS: comp_algo = [Attribute('comp_algo', comp_algo) for comp_algo in compCS]
##        else: comp_algo = [Attribute('comp_algo', 'none')]
##
##        kexAlgs = [e.split('@')[0] for e in self.data["kexAlgs"]]
##        kex_algo = [Attribute('kex_algo', kex_algo) for kex_algo in kexAlgs]
##
##        keyAlgs = [e.split('@')[0] for e in self.data["keyAlgs"]]
##        pub_key_algo = [Attribute('pub_key_algo', pub_key_algo) for pub_key_algo in keyAlgs]
##
##        macCS = [e.split('@')[0] for e in self.data["macCS"]]
##        mac_algo = [Attribute('mac_algo', mac_algo) for mac_algo in macCS]
##
##        hash_att = Attribute('hash', self.data['hassh'], alias=['ssh_kex_hash'])
##
##        ssh_obj = Object('ssh_key_exchange', enc_algo + comp_algo + kex_algo + pub_key_algo + mac_algo + [hash_att])
##
##        self.data = [ssh_obj]
##        self.mal_data = [hash_att]
##        super().__init__()
##
##class ClientSize(Cowrie):
##    def __init__(self, data):
##        self.event_type = 'ssh'
##        self.data, self.data = data.pop("data"), data
##        height_att = Attribute('height', self.data["height"])
##        width_att = Attribute('width', self.data["width"])
##        ssh_client_size_obj = Object('ssh_client_size', [height_att, width_att])
##        self.data = [ssh_client_size_obj]
##        self.mal_data = [ssh_client_size_obj]
##        super().__init__()
##
##class ClientVar(Cowrie):
##    def __init__(self, data):
##        self.event_type = 'ssh'
##        self.data, self.data = data.pop("data"), data
##        env_att = Attribute('ssh_client_env', self.data["msg"])
##        self.data = [env_att]
##        self.mal_data = [env_att]
##        super().__init__()
##
##class ClientVersion(Cowrie):
##    def __init__(self, data):
##        self.event_type = 'ssh'
##        self.data, self.data = data.pop("data"), data
##        ssh_version = self.data["version"]
##        if ssh_version[0] == "'": ssh_version = ssh_version.replace("'", "")
##        ssh_version_att = Attribute('ssh_version', ssh_version)
##        self.data = [ssh_version_att]
##        super().__init__()
