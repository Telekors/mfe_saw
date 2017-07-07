# -*- coding: utf-8 -*-
"""
    mfe_saw.datasource
    ~~~~~~~~~~~~~

    This module imports into the mfe_saw core class to
    provide 'datasource' objects.
"""
import csv
import ipaddress
import inspect
import logging
import re
import sys
from itertools import chain

try:
    from mfe_saw.base import Base
    #from mfe_saw.params import PARAMS
    from mfe_saw.utils import dehexify
except ModuleNotFoundError:
    from base import Base
    #from params import PARAMS
    from utils import dehexify

class DevTree(Base):
    """
    Set of functions to build a DeviceTree object
    """
    def __init__(self, scope=None):
        super().__init__()
        self.scope = scope
        self.devtree = self.get_devtree()
        self.devtree = self.devtree_to_lod(self.devtree)
        self.parent_datasources = self.get_parent_datasources(self.devtree)
        self.clients = self.get_client_groups()
        self.clients = list(chain.from_iterable(self.clients))
        self.devtree = list(chain(self.devtree, self.clients))

    def __iter__(self):
        for self.ds in self.devtree:
            yield self.ds

    def __contains__(self, term):
        self.term = term
        if self.search(term, inc_hostname=True):
            return True
        else:
            return False

    def search(self, term, inc_hostname=False):
        self.term = term
        self.inc_hostname = inc_hostname

        self.search_fields = ['ds_ip', 'name']
        if self.inc_hostname:
            self.search_fields.append('hostname')

        self.found = [ds for field in self.search_fields
                      for ds in self.devtree if ds[field] == term.lower()]

        if self.found:
            return self.found[0]

    def get_devtree(self):
        """
        Get devtree
        """
        self.method, self.data = self.get_params(sys._getframe().f_code.co_name)
        self.callback = self.devtree_cb
        self.resp = self.post(self.method, self.data, self.callback)
        return self.resp

    def devtree_cb(self, resp):
        """
        get_devtree callback to format results
        """
        self.resp = resp
        print(self.resp['ITEMS'])
        self.resp = dehexify(resp['ITEMS'])
        return self.resp

    def devtree_to_lod(self, devtree):
        """
        Parse key fields from raw device strings.
        Return datasources as list of dicts
        """
        self.devtree = devtree
        self.devtree_csv = csv.reader(self.devtree.split('\n'), delimiter=',')
        self.parsed_datasources = []
        for self.row in self.devtree_csv:
            if len(self.row) == 0:
                continue
            if self.row[2] == "3":  # Client group datasource group containers
                self.row.pop(0)     # are fake datasources that seemingly have
                self.row.pop(0)     # two uneeded fields at the beginning.


            self.ds_fields = {'dev_type': self.row[0],
                              'name': self.row[1],
                              'ds_id': self.row[2],
                              'enabled': self.row[15],
                              'ds_ip': self.row[27],
                              'hostname' : self.row[28],
                              'typeID': self.row[16],
                              'vendor': "",
                              'model': "",
                              'tz_id': "",
                              'date_order': "",
                              'port': "",
                              'syslog_tls': "",
                              'client_groups': self.row[29]
                              }
            self.parsed_datasources.append(self.ds_fields)
        return self.parsed_datasources

    def get_client_groups(self):
        """
        Retrieve client lists from each parent group
        """
        self.client_lod = []
        for self.parent in self.parent_datasources:
            self.ds_id = self.parent['ds_id']
            self.resp = self.find_client_group(self.ds_id)
            self.ftoken = self.resp['FTOKEN']
            self.resp = self.get_file(self.ftoken)
            self.client_dict = self.clients_to_lod(self.resp)
            self.client_lod.append(self.client_dict)
        return self.client_lod


    def clients_to_lod(self, clients):
        """
        Parse key fields from 'DS_GETDSCLIENTLIST'.
        Return clients as list of dicts
        """
        self.clients = clients
        self.clients_csv = csv.reader(self.clients.split('\n'), delimiter=',')
        self.parsed_clients = []
        for self.row in self.clients_csv:
            if len(self.row) < 2:
                continue
            if self.row[2] == "3":
                self.row.pop(0)
                self.row.pop(0)
            self.ds_fields = {'dev_type': "0",
                              'name': self.row[1],
                              'id': self.row[0],
                              'enabled': self.row[2],
                              'ds_ip': self.row[3],
                              'hostname' : self.row[4],
                              'typeID': self.row[5],
                              'vendor': self.row[6],
                              'model': self.row[7],
                              'tz_id': self.row[8],
                              'date_order': self.row[9],
                              'port': self.row[11],
                              'syslog_tls': self.row[12],
                              'client_groups': "0"
                              }
            self.parsed_clients.append(self.ds_fields)
        return self.parsed_clients

    def get_parent_datasources(self, ds_summary):
        """
        Parse dict for parent datasources
        Returns dict
        """
        self.ds_summary = ds_summary
        self.ds_parents = []
        for self.ds in self.ds_summary:
            if self.ds['dev_type'] == "3" and int(self.ds['client_groups']) > 0:
                self.ds_parents.append(self.ds)
        return self.ds_parents

    def find_client_group(self, group_id):
        """
        Find client group
        """
        self.group_id = group_id
        self.method, self.data = self.get_params(sys._getframe().f_code.co_name)
        self.resp = self.post(self.method, self.data)
        return self.resp

    def get_file(self, ftoken):
        """
        Exchange token for file
        """
        self.ftoken = ftoken
        self.method, self.data = self.get_params(sys._getframe().f_code.co_name)
        self.resp = self.post(self.method, self.data)
        print(self.resp['DATA'])
        self.resp = dehexify(self.resp['DATA'])
        return self.resp

class Datasource(Base):
    """
    Datasource Class
    Creates Datasource objects
    """
    def __init__(self, dsconf):
        """
        Initialize the Datasource object
        """
        super().__init__()

        if isinstance(dsconf, list):
            self.dsconf = dsconf[0]
        else:
            self.dsconf = dsconf

        try:
            self.dsconf = {self.key: self.val
                           for self.key, self.val in self.dsconf.items()
                           if self.val is not None and self.val != ""}
        except AttributeError:
            raise ValueError("Datasource conf must be dict or list of one dict")

        try:
            self.name = self.dsconf.pop('name')
        except KeyError:
            raise ValueError("Datasource requires 'name'")

        try:
            self._hostname = None
            self._hostname = self.dsconf.pop('hostname')
        except KeyError:
            pass

        try:
            self.ds_ip = self.dsconf.pop('ip')
            print(self.valid_ip(self.ds_ip))
            if self.valid_ip(self.ds_ip):
                print("it's good")
                self._ip = self.ds_ip
            else:
                raise ValueError("Datasource requires a valid IP: {}"
                                 .format(self.ds_ip))
        except KeyError:
            try:
                self.ds_ip = self.dsconf.pop('ipAddress')
                if self.valid_ip(self.ds_ip):
                    self._ip = self.ds_ip
            except KeyError:
                try:
                    if self.hostname is not None:
                        pass
                except KeyError:
                    raise ValueError("Datasource requires valid IP or hostname")

        try:
            self._enabled = self.dsconf.pop('enabled')
        except KeyError:
            self._enabled = "true"

        try:
            self._parent_id = self.dsconf.pop('parent_id')
        except KeyError:
            pass

        try:
            self._rec_id = self.dsconf.pop('rec_id')
        except KeyError:
            pass

        try:
            self._rec_ip = self.dsconf.pop('rec_ip')
        except KeyError:
            pass

        try:
            self._ds_id = self.dsconf.pop('ds_id')
        except KeyError:
            try:
                self._ds_id = self.dsconf.pop('linked_ipsid')
            except KeyError:
                pass

        try:
            self._type_id = self.dsconf.pop('type_id')
        except KeyError:
            try:
                self._type_id = self.dsconf.pop('typeID')
            except KeyError:
                pass
        try:
            self._model = self.dsconf.pop('model')
            self._vendor = self.dsconf.pop('vendor')
        except KeyError:
            pass

        if not self._type_id:
            self._type_id = modven_to_typeid
        if not self._type_id:
            raise ValueError("Datasource must have type_id")

        try:
            self._child_enabled = self.dsconf.pop('childEnabled')
            self._child_count = self.dsconf.pop('childCount')
            self._child_type = self.dsconf.pop('childType')
        except KeyError:
            self._child_enabled = "false"
            self._child_count = "0"
            self._child_type = "0"

        try:
            self._url = self.dsconf.pop('url')
        except KeyError:
            pass

        try:
            self._zone_id = self.dsconf.pop('zone_id')
        except KeyError:
            try:
                self._zone_id = self.dsconf.pop('zoneID')
            except KeyError:
                self._zone_id = "0"

        try:
            self._idm_id = self.dsconf.pop('idm_id')
        except KeyError:
            try:
                self._idm_id = self.dsconf.pop('idmID')
            except KeyError:
                self._idm_id = "0"

        try:
            self._tz_id = self.dsconf.pop("tz_id")
        except KeyError:
            pass

        try:
            self._parsing = self.dsconf.pop("parsing")
        except KeyError:
            self._parsing = "yes"

        try:
            self._elm_logging = self.dsconf.pop("elm_logging")
        except KeyError:
            self._elm_logging = "no"

        try:
            self._pool = self.dsconf.pop("pool")
        except KeyError:
            pass

        try:
            self._require_tls = self.dsconf.pop("require_tls")
        except KeyError:
            self._require_tls = "F"

        try:
            self._syslog_port = self.dsconf.pop('syslog_port')
        except KeyError:
            pass

        try:
            self._user_id = self.dsconf.pop('userID')
        except KeyError:
            pass

        try:
            self._password = self.dsconf.pop('password')
        except KeyError:
            pass


    @staticmethod
    def isprop(v):
        return isinstance(v, property)

    def get_props(self):
        return [prop
                for (prop, val) in inspect.getmembers(Datasource, self.isprop)]

    def __repl__(self):
        return self.name

    @property
    def ip(self):
        return self._ip

    @property
    def parent_id(self):
        return self._parent_id

    @property
    def hostname(self):
        return self._hostname

    @property
    def ds_id(self):
        return self._ds_id

    @property
    def rec_ip(self):
        return self._rec_ip

    @property
    def type_id(self):
        return self._type_id

    @property
    def model(self):
        return self._model

    @property
    def vendor(self):
        return self._vendor

    @property
    def enabled(self):
        return self._enabled

    @property
    def child_enabled(self):
        return self._child_enabled

    @property
    def child_count(self):
        return self._child_count

    @property
    def child_type(self):
        return self._child_type

    @property
    def zone_id(self):
        return self._zone_id

    @property
    def parsing(self):
        return self._parsing

    @property
    def elm_logging(self):
        return self._elm_logging

    @property
    def pool(self):
        return self._pool

    @property
    def require_tls(self):
        return self._require_tls

    @property
    def syslog_port(self):
        return self._syslog_port

    @property
    def user_id(self):
        return self._user_id


    @staticmethod
    def valid_ip(ipaddr):
        """
        Returns True if IPv4/v6 is valid or raises ValueError.

        Args:
            ip: IP address

        Returns:
            True if valid, False if not.
        """
        try:
            ipaddr = str(ipaddress.ip_address(ipaddr))
            return True
        except ValueError:
            return False
