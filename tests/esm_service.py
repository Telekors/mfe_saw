# -*- coding: utf-8 -*-
"""
    mfe_saw utils test
"""
import pytest
import requests

try:
    from mfe_saw.utils import dehexify
except ModuleNotFoundError:
    from .utils.mfe_saw.utils import dehexify

BASE_URL = 'https://22.22.22.60'
VERIFY = False



def get_login():
    resp = requests.post(BASE_URL, verify=VERIFY)
    if resp.status_code == 200:
        return resp
    else:
        return None
    