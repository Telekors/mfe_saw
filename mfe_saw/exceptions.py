# -*- coding: utf-8 -*-
"""
mfe_saw exceptions

"""

class ESMException(Exception):
    """Base Exception"""
    pass

class ESMDataSourceNotFound(ESMException):
    """Raised when the ESM returns an error while: 
    'deserializing ESMDataSourceDetail"""
    pass
