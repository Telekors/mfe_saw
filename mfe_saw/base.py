# -*- coding: utf-8 -*-
"""
    mfe_saw

"""

import ast
import base64
import json
import re
import urllib.parse as urlparse
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3

try:
    from mfe_saw.params import PARAMS
    from mfe_saw.exceptions import ESMAuthError, ESMParamsError
except ModuleNotFoundError:
    from params import PARAMS
    from exceptions import ESMAuthError, ESMParamsError

class Base(object):
    """
    The Base class for mfe_saw objects
    """
    headers = {'Content-Type': 'application/json'}
    baseurl = None
    basepriv = None
    max_workers = 5
    ssl_verify = False
    params = PARAMS

    #def __init__(self, params=PARAMS, **kwargs):
    def __init__(self, **kwargs):
        """
        Base Class for mfe_saw objects.

        """
        #self.params = PARAMS
        self.kwargs = kwargs

        self.uri = None
        self.data = None
        self.url = None
        self.resp = None
        self.host = None
        self.user = None
        self.passwd = None
        self.username = None
        self.password = None
        self.cmd = None
        self.future = None
        self.result = None
        self.method = None


        if not self.ssl_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.ex = ThreadPoolExecutor(max_workers=Base.max_workers,)

    @property
    def name(self):
        """name Getter"""
        return self._name

    @name.setter
    def name(self, name):
        """name setter"""
        if re.search("^[a-zA-Z0-9_-]{1,100}$", name):
            self._name = name
        else:
            raise ValueError("Name not valid")

    def login(self, host, user, passwd):
        """
        The login method
        """
        self.host = host
        self.user = user
        self.passwd = passwd

        Base.baseurl = "https://{}/rs/esm/".format(self.host)
        Base.basepriv = "https://{}/ess".format(self.host)

        self.username = base64.b64encode(self.user.encode('utf-8')).decode()
        self.password = base64.b64encode(self.passwd.encode('utf-8')).decode()
        del self.passwd
        self.url = Base.baseurl + "login"
        self.method, self.data = self.get_params('login')
        self.resp = self.post(self.method, self.data)
        try:
            Base.headers['Cookie'] = self.resp.headers.get('Set-Cookie')
            Base.headers['X-Xsrf-Token'] = self.resp.headers.get('Xsrf-Token')
        except AttributeError:
            raise ESMAuthError()
    def get_params(self, method):
        """
        Look up parameters in params dict
        """
        self.method = method
        self.method, self.data = self.params.get(method)
        self.data = self.data % self.__dict__
        self.data = ast.literal_eval(''.join(self.data.split()))
        return self.method, self.data

    @staticmethod
    def _format_params(cmd, **params):
        """
        Format private API call
        """
        params = {k: v for k, v in params.items() if v is not None}
        params = "%14".join([k + "%13" + v + "%13" for (k, v) in params.items()])
        params = "Request=API%13" + cmd + "%13%14" + params + "%14"
        return params

    @staticmethod
    def _format_priv_resp(resp):
        """
        Format response from private API
        """
        resp = resp.text
        resp = re.search('Response=(.*)', resp).group(1)
        resp = resp.replace('%14', ' ')
        pairs = resp.split()
        formatted = {}
        for pair in pairs:
            pair = pair.replace('%13', ' ')
            pair = pair.split()
            key = pair[0]
            if key == 'ITEMS':
                value = pair[-1]
            else:
                value = urlparse.unquote(pair[-1])
            formatted[key] = value
        return formatted

    def post(self, method, data=None, callback=None):
        """
        Wrapper around _post method
        """
        self.method = method
        self.data = data
        self.callback = callback
        self.url = Base.baseurl + self.method
        if self.method == self.method.upper():
            self.url = Base.basepriv
            self.data = self._format_params(self.method, **self.data)
        else:
            self.url = Base.baseurl + self.method
            if self.data:
                try:
                    self.data = json.dumps(self.data)
                except json.JSONDecodeError:
                    raise ESMParamsError()
        self.future = self.ex.submit(self._post, url=self.url,
                                     data=self.data,
                                     headers=self.headers,
                                     verify=self.ssl_verify)
        self.resp = self.future.result()

        if self.method == self.method.upper():
            self.resp = self._format_priv_resp(self.resp)

        if self.callback:
            self.resp = self.callback(self.resp)
        return self.resp


    def _post(self, url, data=None, headers=None, verify=False):
        """
        Method that actually kicks off the HTTP client.
        """
        self.resp = requests.post(url, data=data, headers=headers, verify=verify)
        self.denied = [400, 401, 403]
        if 200 <= self.resp.status_code <= 300:
            return self.resp
        elif self.resp.status_code in self.denied:
            return (self.resp.status_code, "Not Authorized!")
        else:
            return (self.resp.status_code, self.resp.text)
