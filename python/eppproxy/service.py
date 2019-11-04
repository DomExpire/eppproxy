# -*- coding: utf-8 -*-


# Copyright (c) 2011, Centralnic Ltd
# See LICENSE for details


import subprocess
from email.MIMEBase import MIMEBase
from email.MIMEMultipart import MIMEMultipart
#from email import utils as email_utils

from twisted.internet import reactor, ssl
from twisted.application import service
from twisted.python import log
from twisted.web import util as webutil
from twisted.mail import smtp

from eppproxy import proxy
import conf


class Proxy(service.Service):
    def privilegedStartService(self):
        # get hostname
        p = subprocess.Popen(['hostname'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        self.hostname = stdout.strip("\n")

        # set up error mail
        log.addObserver(self.mailFailure)

        log.msg(conf.SSL_LISTEN_PORT)
        log.msg(conf.SSL_KEY)
        log.msg(conf.SSL_CRT)
        log.msg(conf.EPP_HOST)
        log.msg(conf.EPP_PORT)
        log.msg(conf.CLIENT_SSL_KEY)
        log.msg(conf.CLIENT_SSL_CRT)
        log.msg(conf.USERNAME)
        log.msg(conf.PASSWORD)
        log.msg(conf.CONNECTIONS)
        log.msg(conf.MAIL_FROM)
        log.msg(conf.MAIL_TO_ON_ERROR)

        # init proxy manager
        self.pm = proxy.ProxyManager()

        # start server
        reactor.suggestThreadPoolSize(5)
        if conf.ENABLED:
            self.port = reactor.listenTCP(conf.LISTEN_PORT, proxy.ProxyServerFactory(), interface=conf.INTERFACE)
        if conf.SSL_ENABLED:
            self.ssl_port = reactor.listenSSL(conf.SSL_LISTEN_PORT, proxy.ProxyServerFactory(), ssl.DefaultOpenSSLContextFactory(conf.SSL_KEY, conf.SSL_CRT), interface=conf.INTERFACE)

    def stopService(self):
        self.running = 0
        if conf.ENABLED:
            self.port.stopListening()
        if conf.SSL_ENABLED:
            self.ssl_port.stopListening()

    def mailFailure(self, event):
        if not event['isError']:
            return

        body = None
        if 'failure' in event:
            body = ("<html><head><title>EPP Proxy Traceback (most recent call last)</title></head>"
                    "<body><b>EPP Proxy Traceback (most recent call last):</b>\n\n"
                    "%s\n\n</body></html>\n"
                    % webutil.formatFailure(event['failure']))
        else:
            body = str(event['message'])

        msg = MIMEMultipart()
        msg['From'] = conf.MAIL_FROM
        msg['To'] = ','.join(conf.MAIL_TO_ON_ERROR)
        #msg['Date'] = email_utils.formatdate()
        if 'failure' in event:
            msg['Subject'] = self.hostname + ' - EPP Proxy Failure'
        else:
            msg['Subject'] = self.hostname + ' - EPP Proxy Message'
        html_part = MIMEBase('text', 'html')
        html_part.set_payload(body)
        msg.attach(html_part)
        msg_data = msg.as_string(unixfrom=False)

        def _success(ignore):
            pass
        def _fail(reason):
            pass
        d = smtp.sendmail(conf.SMTP_HOST, conf.MAIL_FROM, conf.MAIL_TO_ON_ERROR, msg_data)
        d.addCallbacks(_success, _fail)
