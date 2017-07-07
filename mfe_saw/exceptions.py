# -*- coding: utf-8 -*-
"""
mfe_saw exceptions

"""

class ESMException(Exception):
    """Base Exception"""
    pass

class ESMParamsError(ESMException):
    """Raised when params aren't parsable"""
    pass


class ESMAuthError(ESMException):
    """Indicate a login failure"""
    pass
