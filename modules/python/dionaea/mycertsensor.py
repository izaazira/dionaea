from dionaea.core import ihandler, incident, g_dionaea
from dionaea import IHandlerLoader

import logging
import json
import uuid
import time

try:
    import magic
except:
    def filetype(fpath):
        return ''
else:
    def filetype(fpath):
        try:
            mc = magic.Magic()
            ftype = mc.from_file(fpath)
        except:
            ftype = ''
        return ftype

logger = logging.getLogger('mycertsensor')
logger.setLevel(logging.DEBUG)

class MyCERTSensorHandlerLoader(IHandlerLoader):
    name = "mycertsensor"

    @classmethod
    def start(cls, config=None):
        return handler("*", config=config)

class handler(ihandler):
    def __init__(self, path, config=None):
        logger.info("%s ready!" % (self.__class__.__name__))
        ihandler.__init__(self, path)

        self.sensorid = config.get("sensorid")
        self.connection_url = config.get("connection_url").format(id=self.sensorid)
        self.artifact_url = config.get("artifact_url")
        self.file_fieldname = config.get("file_fieldname")
        self.cookies = {}
        self.attacker = {}
        self.connection = {}
        self.mysql = {}
        self.mssql = {}
        self.ftp = {}

    def handle_incident_dionaea_modules_python_mycertsensor_connection_result(self, icd):
        logger.info("MyCERT Sensor: icd.path - %s" % icd.path)
        with open(icd.path, mode='r') as f:
            content = f.read()
        logger.info("MyCERT Sensor: icd.content - %s" % content)
        j = json.loads(content)
        logger.info("MyCERT Sensor: Attacker ID: %d" % j['id'])
        cookie = icd._userdata
        con = self.cookies[cookie]
        self.attacker[con] = (j['id'],  j['id'])


    def handle_incident_dionaea_modules_python_mycertsensor_artifact_result(self, icd):
        logger.info("MyCERT Sensor: icd.path - %s" % icd.path)
        with open(icd.path, mode='r') as f:
            content = f.read()
        logger.info("MyCERT Sensor Artifact: icd.content - %s" % content)
        logger.info("MyCERT Sensor Artifact: icd._userdata - %s" % icd._userdata)
        resp = json.loads(content)
        udata = json.loads(icd._userdata)
        if resp['error'] == True:
            self.submitArtifact(udata['connection_id'], udata['jenis'], json.dumps(udata['metadata']));

    def connection_insert(self, icd, connection_type):
        con = icd.con
        if(con.protocol != 'pcap'):
            cookies = str(uuid.uuid4())
            logger.info("MyCERT Sensor: connection_type: %s, con_protocol: %s" % (connection_type, con.protocol))
            i = incident('dionaea.upload.request')
            i._url = self.connection_url
            i.sensorid = self.sensorid
            # i.connection_type = connection_type
            i.protocol = con.protocol
            i.transport = con.transport
            i.hostname = con.remote.hostname
            i.src_ip = con.remote.host
            i.src_port = str(con.remote.port)
            i.dst_ip = con.local.host
            i.dst_port = str(con.local.port)
            i.timestamp = str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            i.hash = cookies
            i._callback = "dionaea.modules.python.mycertsensor.connection_result"
            i._userdata = cookies
            self.cookies[cookies] = con
            self.connection[con] = cookies;
            i.report()

    def submitArtifact(self, connection_id, jenis, metadata):
        url = self.artifact_url.format(id=self.sensorid, connection_id=connection_id)
        logger.info("MyCERT Sensor: Submit Artifact url=%s, jenis=%s,connection_id=%s" % (url, jenis, connection_id))
        i = incident('dionaea.upload.request')
        i._url = url
        i.type = jenis
        i.metadata = metadata
        i._callback = "dionaea.modules.python.mycertsensor.artifact_result"
        i._userdata = json.dumps({
            'connection_id': connection_id,
            'jenis': jenis,
            'metadata': json.loads(metadata)
        })
        i.report()

    def handle_incident_dionaea_modules_python_pptp_connect(self, icd):
        logger.info("MyCERT Sensor: handle_incident_dionaea_modules_python_pptp_connect")
        self.submitArtifact(str(self.connection[icd.con]), 'pptp_connect', json.dumps({
            'firmware_revision': icd.firmware_revision,
            'protocol_version': icd.protocol_version,
            'remote_hostname': icd.remote_hostname,
            'vendor_name': icd.vendor_name,
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        }))

    def handle_incident_dionaea_modules_python_mqtt_subscriber(self, icd):
        logger.info("MyCERT Sensor: handle_incident_dionaea_modules_python_mqtt_subscriber")
        self.submitArtifact(str(self.connection[icd.con]), 'mqtt_subscriber', json.dumps({
            'messageid': icd.subscribemessageid,
            'topic': icd.subscribetopic,
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        }))

    def handle_incident_dionaea_modules_python_mqtt_publish(self, icd):
        logger.info("MyCERT Sensor: handle_incident_dionaea_modules_python_mqtt_publish")
        self.submitArtifact(str(self.connection[icd.con]), 'mqtt_publish', json.dumps({
            'topic': icd.publishtopic,
            'message': icd.publishmessage,
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        }))

    def handle_incident_dionaea_modules_python_mqtt_connect(self, icd):
        logger.info("MyCERT Sensor: handle_incident_dionaea_modules_python_mqtt_connect")
        self.submitArtifact(str(self.connection[icd.con]), 'mqtt_connect', json.dumps({
            'clientid': icd.clientid,
            'willtopic': icd.willtopic,
            'willmessage': icd.willmessage,
            'username': icd.username,
            'password': icd.password,
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        }))

    def handle_incident_dionaea_download_offer(self, icd):
        logger.info("MyCERT Sensor: handle_incident_dionaea_download_offer")
        self.submitArtifact(str(self.connection[icd.con]), 'uploadattempt', json.dumps({
            'repo_url': icd.url,
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        }))

    def handle_incident_dionaea_download_complete_hash(self, icd):
        logger.info("MyCERT Sensor: handle_incident_dionaea_download_complete_hash")
        i = incident("dionaea.upload.request")
        i._url = self.artifact_url.format(id=self.sensorid, connection_id=str(self.connection[icd.con]))
        i.type = "fileupload"
        i.md5 = icd.md5hash
        i.metadata = json.dumps({
            'url': icd.url,
            'md5': icd.md5hash,
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        })
        i.set('file://' + self.file_fieldname, icd.file)
        i.report()

    def handle_incident_dionaea_module_emu_profile(self, icd):
        logger.info("MyCERT Sensor: handle_incident_dionaea_module_emu_profile")
        self.submitArtifact(str(self.connection[icd.con]), 'libemu', json.dumps({
            'profile': icd.profile,
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        }))

    def handle_incident_dionaea_service_shell_listen(self, icd):
        logger.info("MyCERT Sensor: handle_incident_dionaea_service_shell_listen")
        self.submitArtifact(str(self.connection[icd.con]), 'libemu_shell', json.dumps({
            'shell': "bindshell://"+str(icd.port),
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        }))

    def handle_incident_dionaea_service_shell_connect(self, icd):
        logger.info("MyCERT Sensor: handle_incident_dionaea_service_shell_connect")
        self.submitArtifact(str(self.connection[icd.con]), 'libemu_shell', json.dumps({
            'shell': "connectbackshell://"+str(icd.host)+":"+str(icd.port),
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        }))

    def handle_incident_dionaea_modules_python_mssql_login(self, icd):
        logger.info("MyCERT Sensor: handle_incident_dionaea_modules_python_mssql_login")
        self.submitArtifact(str(self.connection[icd.con]), 'bruteforce', json.dumps({
            'username': icd.username,
            'password': icd.password,
            'success': 'yes',
            'source': 'mssql',
            'hostname': icd.hostname,
            'appname': icd.appname,
            'cltintname': icd.cltintname,
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        }))

    def handle_incident_dionaea_modules_python_mysql_login(self, icd):
        logger.info("MyCERT Sensor: handle_incident_dionaea_modules_python_mysql_login")
        self.submitArtifact(str(self.connection[icd.con]), 'bruteforce', json.dumps({
            'username': icd.username,
            'password': icd.password,
            'success': 'yes',
            'source': 'mysql',
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        }))

    def handle_incident_dionaea_modules_python_ftp_login(self, icd):
        logger.info("MyCERT Sensor: handle_incident_dionaea_modules_python_ftp_login")
        self.submitArtifact(str(self.connection[icd.con]), 'bruteforce', json.dumps({
            'username': icd.ftp_user,
            'password': icd.ftp_user,
            'success': 'yes',
            'source': 'ftp',
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        }))

    def handle_incident_dionaea_modules_python_mysql_command(self, icd):
        if hasattr(icd, 'args'):
            args = json.dumps(icd.args)
        else:
            args = json.dumps({})

        self.submitArtifact(str(self.connection[icd.con]), 'mysqlcmd', json.dumps({
            'cmd': icd.command,
            'args': args,
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        }))

    def handle_incident_dionaea_modules_python_ftp_cmd(self, icd):
        pass

    def handle_incident_dionaea_modules_python_mssql_cmd(self, icd):
        self.submitArtifact(str(self.connection[icd.con]), 'mssqlcmd', json.dumps({
            'cmd': icd.cmd,
            'status': icd.status,
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        }))

    def handle_incident_dionaea_modules_python_upnp_request(self, icd):
        self.submitArtifact(str(self.connection[icd.con]), 'upnp_request', json.dumps({
            'headers': icd.headers,
            'data': icd.data,
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        }))

    def handle_incident_dionaea_modules_python_smb_doublepulsar_command(self, icd):
        self.submitArtifact(str(self.connection[icd.con]), 'doublepulsar_cmd', json.dumps({
            'command': icd.command,
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        }))

    def handle_incident_dionaea_modules_python_smb_doublepulsar_payload(self, icd):
        self.submitArtifact(str(self.connection[icd.con]), 'doublepulsar_payload', json.dumps({
            'encrypted_hash': icd.encrypted_hash,
            'decrypted_hash': icd.decrypted_hash,
            'timestamp': str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        }))

    def handle_incident_dionaea_modules_python_http_webattack_modsec(self, icd):
        self.submitArtifact(str(self.connection[icd.con]), 'webattack', icd.modsec)

    def handle_incident_dionaea_connection_tcp_listen(self, icd):
        self.connection_insert( icd, 'listen')

    def handle_incident_dionaea_connection_tls_listen(self, icd):
        self.connection_insert( icd, 'listen')

    def handle_incident_dionaea_connection_tcp_connect(self, icd):
        self.connection_insert( icd, 'connect')

    def handle_incident_dionaea_connection_tls_connect(self, icd):
        self.connection_insert( icd, 'connect')

    def handle_incident_dionaea_connection_udp_connect(self, icd):
        self.connection_insert( icd, 'connect')

    def handle_incident_dionaea_connection_tcp_accept(self, icd):
        self.connection_insert( icd, 'accept')

    def handle_incident_dionaea_connection_tls_accept(self, icd):
        self.connection_insert( icd, 'accept')

    def handle_incident_dionaea_connection_tcp_reject(self, icd):
        self.connection_insert(icd, 'reject')

    def handle_incident_dionaea_connection_tcp_pending(self, icd):
        self.connection_insert(icd, 'pending')

    def handle_incident_dionaea_connection_free(self, icd):
        con = icd.con
        if con in self.attacker:
            logger.info("MyCERT Sensor: attacker id %d is done" % self.attacker[icd.con][1])
            del self.attacker[con]

        if con in self.connection:
            del self.connection[con]
