#!/usr/bin/env python
# -*- coding: UTF-8 -*-

__author__ = "Marcelo Souza"
__license__ = "GPL"

# Config
from configobj import ConfigObj, ConfigObjError
cfg = None

#
# Read ConfigObj from file
#
def read_cfg(filename):
    cfg_obj = None
    try:
        cfg_obj = ConfigObj(filename, raise_errors=True, file_error=True)
    except Exception as e:
        # TODO - enhance error handling here
        cfg_obj = None        
    return cfg_obj