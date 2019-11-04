# -*- coding: utf-8 -*-


# Copyright (c) 2011, Centralnic Ltd
# See LICENSE for details


import struct
import cStringIO
import re
from datetime import datetime
import time
from xml.sax import parseString, handler

from twisted.internet import reactor, protocol, ssl
from twisted.python import log

from OpenSSL import SSL

from eppproxy import utils as proxy_utils
import conf


class CodeMsgHandler(handler.ContentHandler):
    def __init__(self):
        self.code = None
        self.msg = None
        self.is_msg_element = False

    def startElement(self, name, attrs):
        if name == 'result':
            self.code = attrs.get('code', None)
        elif name == 'msg':
            self.msg = ''
            self.is_msg_element = True

    def characters(self, ch):
        if self.is_msg_element:
            self.msg = ch

    def endElement(self, name):
        if name == 'msg':
            self.is_msg_element = False

class CommandHandler(handler.ContentHandler):
    def __init__(self):
        self.isNextCommand = None
        self.command = None

    def startElement(self, name, attrs):
        if name == 'command':
            self.isNextCommand = True
        elif self.isNextCommand is True:
            self.command = name
            self.isNextCommand = None

class LoginHandler(handler.ContentHandler):
    def __init__(self):
        self.uname = None
        self.pword = None
        self.trid = None
        self.is_uname_element = False
        self.is_pword_element = False
        self.is_trid_element = False

    def startElement(self, name, attrs):
        if name == 'clID':
            self.uname = ''
            self.is_uname_element = True
        elif name == 'pw':
            self.pword = ''
            self.is_pword_element = True
        elif name == 'clTRID':
            self.trid = ''
            self.is_trid_element = True

    def characters(self, ch):
        if self.is_uname_element:
            self.uname = ch
        elif self.is_pword_element:
            self.pword = ch
        elif self.is_trid_element:
            self.trid = ch

    def endElement(self, name):
        if name == 'clID':
            self.is_uname_element = False
        elif name == 'pw':
            self.is_pword_element = False
        elif name == 'clTRID':
            self.is_trid_element = False


class SSLCtxFactory(ssl.ClientContextFactory):
    def getContext(self):
        self.method = SSL.SSLv23_METHOD
        ctx = ssl.ClientContextFactory.getContext(self)
        ctx.use_certificate_file(conf.CLIENT_SSL_CRT)
        ctx.use_privatekey_file(conf.CLIENT_SSL_KEY)
        return ctx


class ProxyManager(proxy_utils.Singleton):
    def __init__(self):
        if not hasattr(self, '_init_done'):
            self._init_done = True
            self.connections = {}
            self.server_to_client = {}
            self.cc = protocol.ClientCreator(reactor, ProxyClientProtocol)
            if not conf.CLIENT_SSL_KEY is None and not conf.CLIENT_SSL_KEY is None:
                self.ccf = SSLCtxFactory()
            else:
                self.ccf = ssl.ClientContextFactory()

    def registerServerProtocol(self, login_frame, server_protocol):
        # extract username and password
        handler = LoginHandler()
        parseString(login_frame, handler)
        if handler.uname is None:
            log.err("Cant find username in client login frame, disconnecting client.")
            server_protocol.transport.loseConnection()
            return
        username = handler.uname.strip().encode('UTF-8')

        if handler.pword is None:
            log.err("Cant find password in client login frame, disconnecting client.")
            server_protocol.transport.loseConnection()
            return
        password = handler.pword.strip().encode('UTF-8')

        # extract clTRID, if any
        cltrid = None
        if not handler.trid is None:
            cltrid = handler.trid.encode('UTF-8')

        # try to register with exisiting connection
        if username in self.connections:
            the_dict = self.connections[username]
            for client_protocol in the_dict['protocols']:
                if client_protocol.server_protocol is None:
                    if not the_dict['password'] == password:
                        log.err("Client password does not match cache, disconnecting client.")
                        server_protocol.transport.loseConnection()
                        return
                    client_protocol.server_protocol = server_protocol
                    server_protocol.client_protocol = client_protocol
                    self.server_to_client[server_protocol] = client_protocol
                    if not cltrid is None:
                        response = re.sub(r'<clTRID>.+</clTRID>', '<clTRID>' + cltrid + '</clTRID>', client_protocol.login_response_frame)
                        server_protocol.sendFrame(response)
                    else:
                        server_protocol.sendFrame(client_protocol.login_response_frame)
                    log.msg("REUSING CONNECTION TO EPP SERVER")
                    return

        # ok we could not find free existing connection
        def _success(client_protocol):
            if not username in self.connections:
                self.connections[username] = {
                        'password': password,
                        'protocols': [client_protocol]}
            else:
                self.connections[username]['protocols'].append(client_protocol)
            self.server_to_client[server_protocol] = client_protocol
            client_protocol.login_frame = login_frame
            client_protocol.server_protocol = server_protocol
            server_protocol.client_protocol = client_protocol
            client_protocol.username = username
        def _fail(reason):
            log.err(reason)
            log.err("Failed connecting to master EPP server, disconnecting client.")
            server_protocol.transport.loseConnection()
        log.msg("CREATING NEW CONNECTION TO EPP SERVER")
        self.cc.connectSSL(conf.EPP_HOST, conf.EPP_PORT, self.ccf).addCallbacks(_success, _fail)

    def deregisterServerProtocol(self, server_protocol):
        log.msg("DEREGISTER SERVER PROTOCOL")
        if server_protocol in self.server_to_client:
            client_protocol = self.server_to_client[server_protocol]
            client_protocol.server_protocol = None
            del self.server_to_client[server_protocol]
        server_protocol.client_protocol = None

    def deregisterClientProtocol(self, client_protocol):
        log.msg("DEREGISTER CLIENT PROTOCOL")
        uname = client_protocol.username
        login_frame = client_protocol.login_frame
        if uname in self.connections:
            if client_protocol in self.connections[uname]['protocols']:
                self.connections[uname]['protocols'].remove(client_protocol)
            if client_protocol.invalid_login:
                return
            have = len(self.connections[uname]['protocols'])
            if have < conf.CONNECTIONS:
                for x in xrange(abs(have - conf.CONNECTIONS)):
                    def _success(client_protocol):
                        self.connections[uname]['protocols'].append(client_protocol)
                        client_protocol.login_frame = login_frame
                        client_protocol.username = uname
                    def _fail(reason):
                        log.err(reason)
                    log.msg("CREATING NEW CONNECTION TO EPP SERVER")
                    self.cc.connectSSL(conf.EPP_HOST, conf.EPP_PORT, self.ccf).addCallbacks(_success, _fail)


GENERIC_ERROR = '''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
    <response>
    <result code="%s">
      <msg>%s</msg>
    </result>
    <trID>
      <svTRID>%s</svTRID>
    </trID>
  </response>
</epp>'''


class EPPProtocol(protocol.Protocol):
    """
    Quick hack of NetstringReceiver.
    """
    _PARSING_LENGTH = 0
    _PARSING_PAYLOAD = 1

    def makeConnection(self, transport):
        protocol.Protocol.makeConnection(self, transport)
        self._remaining_data = ""
        self._current_payload_size = 0
        self._payload = cStringIO.StringIO()
        self._state = self._PARSING_LENGTH
        self._expected_payload_size = 0
        self.broken_peer = 0

        self._dont_have_enough = False

    def connectionMade(self):
        pass

    def dataReceived(self, data):
        self._dont_have_enough = False
        self._remaining_data += data
        while self._remaining_data:
            if (self._state == 0 and self._dont_have_enough):
                break
            try:
                self._consumeData()
            except:
                log.err()
                log.err("EPP protocol error, disconnecting client.")
                self.transport.loseConnection()
                self.brokenPeer = 1
                # make sure we send error frame on server_protocol
                if hasattr(self, 'server_protocol') and not self.server_protocol is None:
                    self.server_protocol.sendFrame(GENERIC_ERROR % ('2999', 'Protocol error.', 'PROXY-%s' % (str(time.time()),)))
                    self.server_protocol.transport.loseConnection()
                break

    def _consumeData(self):
        if self._state == self._PARSING_LENGTH:
            self._consumeLength()
            self._prepareForPayloadConsumption()
        elif self._state == self._PARSING_PAYLOAD:
            self._consumePayload()

    def _consumeLength(self):
        if len(self._remaining_data) >= 4:
            self._processLength()
        else:
            self._dont_have_enough = True

    def _processLength(self):
        length = self._remaining_data[:4]
        length = struct.unpack('!i', length)[0] - 4

        self._expected_payload_size = length
        self._remaining_data = self._remaining_data[4:]

    def _prepareForPayloadConsumption(self):
        self._state = self._PARSING_PAYLOAD
        self._current_payload_size = 0
        self._payload.seek(0)
        self._payload.truncate()

    def _consumePayload(self):
        self._extractPayload()
        if self._current_payload_size < self._expected_payload_size:
            raise Exception("Incomplete payload!")
        self._state = self._PARSING_LENGTH
        self._processPayload()

    def _extractPayload(self):
        if self._payloadComplete():
            remaining_payload_size = (self._expected_payload_size -
                    self._current_payload_size)
            self._payload.write(self._remaining_data[:remaining_payload_size])
            self._remaining_data = self._remaining_data[remaining_payload_size:]
            self._current_payload_size = self._expected_payload_size
        else:
            self._payload.write(self._remaining_data)
            self._current_payload_size += len(self._remaining_data)
            self._remaining_data = ""

    def _payloadComplete(self):
        return (len(self._remaining_data) + self._current_payload_size >=
                self._expected_payload_size)

    def _processPayload(self):
        self.frameReceived(self._payload.getvalue())

    def frameReceived(self, frame):
        pass

    def sendFrame(self, data):
        data = data.replace('{{username}}', conf.USERNAME)
        data = data.replace('{{password}}', conf.PASSWORD)
        self.transport.write(struct.pack('!i', len(data) + 4) + data)


GREETING = '''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
    <greeting>
        <svID>CentralNic tx-epp-proxy</svID>
        <svDate>%s</svDate>
        <svcMenu>
            <version>1.0</version>
            <lang>en</lang>
            <objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>
            <objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>
            <objURI>urn:ietf:params:xml:ns:host-1.0</objURI>
            <svcExtension>
                <extURI>urn:centralnic:params:xml:ns:wf-1.0</extURI>
                <extURI>urn:centralnic:params:xml:ns:ttl-1.0</extURI>
                <extURI>urn:ietf:params:xml:ns:rgp-1.0</extURI>
                <extURI>urn:ietf:params:xml:ns:secDNS-1.0</extURI>
                <extURI>http://www.verisign.com/epp/sync-1.0</extURI>
                <extURI>http://www.cloudregistry.net/ns/launchphase-1.0</extURI>
            </svcExtension>
        </svcMenu>
        <dcp>
            <access>
                <all></all>
            </access>
            <statement>
                <purpose>
                    <admin></admin>
                    <prov></prov>
                </purpose>
                <recipient>
                    <ours></ours>
                    <public></public>
                </recipient>
                <retention>
                    <stated></stated>
                </retention>
            </statement>
        </dcp>
    </greeting>
</epp>'''


class ProxyServerProtocol(EPPProtocol):
    """
    Protocol to serve the proxy clients.
    """
    def makeConnection(self, transport):
        EPPProtocol.makeConnection(self, transport)
        self.client_protocol = None

    def connectionMade(self):
        self.sendFrame(GREETING % (datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),))

    def dataReceived(self, data):
        EPPProtocol.dataReceived(self, data)

    def frameReceived(self, frame):
        if self.client_protocol is None:
            pm = ProxyManager()
            pm.registerServerProtocol(frame, self)
        else:
            handler = CommandHandler()
            parseString(frame, handler)
            if handler.command is not None and handler.command in ['create', 'check', 'logout']:
                self.client_protocol.sendFrame(frame)
            else:
                log.msg(frame)
                log.msg(handler.command)

    def connectionLost(self, reason):
        pm = ProxyManager()
        pm.deregisterServerProtocol(self)


class ProxyServerFactory(protocol.Factory):
    protocol = ProxyServerProtocol


class ProxyClientProtocol(EPPProtocol):
    """
    Protocol to manage client connections to master EPP server.
    """
    def connectionMade(self):
        pass

    def makeConnection(self, transport):
        EPPProtocol.makeConnection(self, transport)
        self.server_protocol = None
        self._got_greeting = False
        self._got_login_response = False
        self.login_frame = None
        self.login_response_frame = None
        self.username = None
        self.invalid_login = False

    def dataReceived(self, data):
        if self._got_greeting and self._got_login_response and not self.server_protocol is None:
            self.server_protocol.transport.write(data)
            return
        EPPProtocol.dataReceived(self, data)

    def frameReceived(self, frame):
        if not self._got_greeting:
            self._got_greeting = True
            if self.login_frame is None:
                raise Exception('login_frame is None, this should not happen!')
            self.sendFrame(self.login_frame)
            return
        if not self._got_login_response:
            self._got_login_response = True
            self.login_response_frame = frame

            handler = CodeMsgHandler()
            parseString(frame, handler)

            if handler.code is None:
                if not self.server_protocol is None:
                    log.err("Can not find login code in response from master EPP server, disconnecting client.")
                    self.server_protocol.transport.loseConnection()
                return
            code = int(handler.code)

            if not code == 1000:
                if not self.server_protocol is None:
                    log.err("Login code is not '1000', disconnecting client.")
                    self.server_protocol.sendFrame(frame)
                    self.server_protocol.transport.loseConnection()
                self.invalid_login = True
                self.transport.loseConnection()
                return
            if not self.server_protocol is None:
                self.server_protocol.sendFrame(frame)
            return
        #raise Exception('We should never get to here!')
        pass

    def connectionLost(self, reason):
        pm = ProxyManager()
        pm.deregisterClientProtocol(self)
