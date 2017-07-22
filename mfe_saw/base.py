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
    from mfe_saw.exceptions import ESMException, ESMDataSourceNotFound
except ImportError:
    from params import PARAMS
    from exceptions import ESMException, ESMDataSourceNotFound

class Base(object):
    """
    The Base class for mfe_saw objects
    """
    _headers = {'Content-Type': 'application/json'}
    _baseurl = None
    _basepriv = None
    _max_workers = 10
    _ssl_verify = False
    _params = PARAMS
    
    def __init__(self, **kwargs):
        """
        Base Class for mfe_saw objects.

        """
        self._kwargs = kwargs

        self._url = None
        self._data = None
        self._uri = None
        self._resp = None
        self._host = None
        self._user = None
        self._passwd = None
        self._username = None
        self._password = None
        self._cmd = None
        self._future = None
        self._result = None
        self._method = None
        self._name = None

        if not self._ssl_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self._ex = ThreadPoolExecutor(max_workers=Base._max_workers,)

    def login(self, host, user, passwd):
        """
        The login method
        """
        self._host = host
        self._user = user
        self._passwd = passwd

        Base._baseurl = 'https://{}/rs/esm/'.format(self._host)
        Base._basepriv = 'https://{}/ess'.format(self._host)

        self._username = base64.b64encode(self._user.encode('utf-8')).decode()
        self._password = base64.b64encode(self._passwd.encode('utf-8')).decode()
        del self._passwd
        self._url = Base._baseurl + 'login'
        self._method, self._data = self._get_params('login')
        self._resp = self.post(self._method, self._data, raw=True)
        try:
            Base._headers['Cookie'] = self._resp.headers.get('Set-Cookie')
            Base._headers['X-Xsrf-Token'] = self._resp.headers.get('Xsrf-Token')
        except AttributeError:
            raise ESMAuthError()
            
    def _get_params(self, method):
        """
        Look up parameters in params dict
        """
        self._method = method
        self._method, self.data = self._params.get(self._method)
        self._data = self.data % self.__dict__
        self._data = ast.literal_eval(''.join(self._data.split()))
        return self._method, self._data

    @staticmethod
    def _format_params(cmd, **params):
        """
        Format private API call
        """
        params = {k: v for k, v in params.items() if v is not None}
        params = '%14'.join([k + '%13' + v + '%13' for (k, v) in params.items()])
        
        if params:
            params = 'Request=API%13' + cmd + '%13%14' + params + '%14'
        else:
            params = 'Request=API%13' + cmd + '%13%14'
        return params

    @staticmethod
    def _format_priv_resp(resp):
        """
        Format response from private API
        """
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

    def post(self, method, data=None, callback=None, raw=False):
        """
        Wrapper around _post method
        """
        self._method = method
        self._data = data
        self._callback = callback
        self._raw = raw
        
        if not self._method:
            raise ValueError("Method must not be None")
        
        self._url = Base._baseurl + self._method
        
        if self._method == self._method.upper():
            self._url = Base._basepriv
            self._data = self._format_params(self._method, **self._data)
        else:
            self._url = Base._baseurl + self._method
            if self._data:
                try:
                    self._data = json.dumps(self._data)
                except json.JSONDecodeError:
                    raise ESMParamsError()

        self._future = self._ex.submit(self._post, url=self._url,
                                     data=self._data,
                                     headers=self._headers,
                                     verify=self._ssl_verify)
        self._resp = self._future.result()

        if self._raw:
            return self._resp

        if 200 <= self._resp.status_code <= 300:
            try:
                self._resp = self._resp.json()
                self._resp = self._resp.get('return')
            except json.decoder.JSONDecodeError:
                self._resp = self._resp.text
            if self._method == self._method.upper():
                self._resp = self._format_priv_resp(self._resp)
            if self._callback:
                self._resp = self._callback(self._resp)
            return self._resp
        elif self._resp.status_code == 400: 
            if self._resp.text.startswith('Error deserializing EsmDataSourceDetail'):
                raise ESMDataSourceNotFound
        

    def _post(self, url, data=None, headers=None, verify=False):
        """
        Method that actually kicks off the HTTP client.
        
        Args:
            url (str): URL to send the post to.
            data (str): Any payload data for the post.
            headers (str): http headers that hold cookie data after 
                            authentication.
            verify (bool): SSL cerificate verification 
        
        Returns:
            Requests Response object
        """
        self._url = url
        self._data = data
        self._headers = headers
        self._verify = verify
        return requests.post(self._url, 
                                    data=self._data, 
                                    headers=self._headers, 
                                    verify=self._verify)