# -*- coding: utf-8 -*-


# Copyright (c) 2011, Centralnic Ltd
# See LICENSE for details


import os
import sys
sys.path.insert(0, '.')

from twisted.application import service
from twisted.python.log import ILogObserver, FileLogObserver
from twisted.python.logfile import DailyLogFile

from eppproxy.service import Proxy


app_home = os.path.dirname(os.path.abspath(__file__))
foreground = '-noy' in sys.argv
log_dir = os.path.join(app_home, 'log')

application = service.Application('eppproxy')
if not foreground:
    logfile = DailyLogFile("proxy.log", log_dir)
    application.setComponent(ILogObserver, FileLogObserver(logfile).emit)

proxy = Proxy()
proxy.app_home = app_home
proxy.setServiceParent(application)

# vim:filetype=python
