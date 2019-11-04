# -*- coding: utf-8 -*-


# Copyright (c) 2011, Centralnic Ltd
# See LICENSE for details


class Singleton(object):
    _instance = None
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Singleton, cls).__new__(cls, *args, **kwargs)
        return cls._instance
