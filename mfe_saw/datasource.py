# -*- coding: utf-8 -*-
"""
    mfe_saw.datasource
    ~~~~~~~~~~~~~

    This module imports into the mfe_saw core class to
    provide 'DevTree' and 'DataSource' objects.
"""
import csv
import ipaddress
import inspect
import json
import logging
import re
import sys
from itertools import chain
from io import StringIO
from functools import lru_cache


try:
    from mfe_saw.base import Base
    from mfe_saw.esm import ESM
    from mfe_saw.utils import dehexify
    from mfe_saw.exceptions import ESMException
except ImportError:
    from base import Base
    from esm import ESM
    from utils import dehexify
    from exceptions import ESMException

class DevTree(Base):
    """
    Interface to the ESM device tree.
    """
    _DevTree = []
    
    def __init__(self):
        """Coordinates assembly of the devtree"""
        super().__init__()
        if Base._baseurl == None:
            raise ESMException('ESM URL not set. Are you logged in?')
        
        if not DevTree._DevTree:
            self._esm = ESM()
            self._devtree = self._get_devtree()
            self._devtree = self.devtree_to_lod(self._devtree)
            self._devtree = self._add_parent_ids(self._devtree)
            self._parent_datasources = self.get_parent_datasources(self._devtree)
            self._clients = self.get_client_groups()
            self._clients = list(chain.from_iterable(self._clients))
            self._devtree = list(chain(self._devtree, self._clients))
            self._devtree = self._add_venmods(self._devtree)
            DevTree._DevTree = self._devtree

            
    def __len__(self):
        """
        Returns the count of devices in the device tree.
        """
        return len(DevTree._DevTree)
        
    def __iter__(self):
        """
        Returns:
            Generator with datasource objects.
        """
        for self._ds in DevTree._DevTree:
            yield self._ds

    def __contains__(self, term):
        """
        Returns:
            bool: True/False the name or IP matches the provided search term.
        """
        self._cterm = term
        if self.search(self._cterm, inc_hostname=True):
            return True
        else:
            return False

    def search(self, term, inc_hostname=False, zone_id=0):
        """
        Args:
            term (str): Datasource name, IP (or hostname) if inc_hostname 
            
            inc_hostname (bool): Search the hostname
            
            zone_id (int): Provide zone_id to limit search to a specific zone

        Returns:
            Datasource object that matches the provided search term or None.
        """
        self._term = term
        self._inc_hostname = inc_hostname

        self._search_fields = ['ds_ip', 'name']
        if self._inc_hostname:
            self._search_fields.append('hostname')
        
        self._found = [self._found_ds for self._field in self._search_fields
                      for self._found_ds in DevTree._DevTree
                      if self._found_ds[self._field].lower() == self._term.lower()]
                    
        if self._found:
            return self._found[0]
    
    @lru_cache(maxsize=None)
    def _get_devtree(self):
        """
        Returns:
            ESM device tree; raw, but ordered, string in need of parsing.
            Does not include client datasources.
        """
        self._method, self._data = self.get_params('get_devtree')
        self._resp = self.post(self._method, self._data)
        return dehexify(self._resp['ITEMS'])

    def devtree_to_lod(self, devtree):
        """
        Parse key fields from raw device strings.
        Return datasources as list of dicts
        """
        self._devtree = devtree
        self._devtree_io = StringIO(self._devtree)
        self._devtree_csv = csv.reader(self._devtree_io, delimiter=',')
        self._devtree_lod = []
        self._pid = None
        for self._row in self._devtree_csv:
            if len(self._row) == 0:
                continue
            if self._row[2] == "3":  # Client group datasource group containers
                self._row.pop(0)     # are fake datasources that seemingly have
                self._row.pop(0)     # two uneeded fields at the beginning.
            self._ds_fields = {'_dev_type': self._row[0],
                               'name': self._row[1],
                               'ds_id': self._row[2],
                               'enabled': self._row[15],
                               'ds_ip': self._row[27],
                               'hostname' : self._row[28],
                               'type_id': self._row[16],
                               'vendor': "",
                               'model': "",
                               'tz_id': "",
                               'date_order': "",
                               'port': "",
                               'syslog_tls': "",
                               'client_groups': self._row[29]
                               }
            self._devtree_lod.append(self._ds_fields)
        return self._devtree_lod

    def get_client_groups(self):
        """
        Retrieve client lists from each parent group
        
        Args:
            ds_id (str): Parent ds_id(s) are collected on init
            ftoken (str): Set and used after requesting clients for ds_id
        
        Returns:
            List of dicts representing all of the client data sources 
        """
        self.client_lod = []
        for self.parent in self._parent_datasources:
            self.ds_id = self.parent['ds_id']
            self._resp = self.find_client_group(self.ds_id)
            self._ftoken = self._resp['FTOKEN']
            self._resp = self.get_file(self._ftoken)
            self.client_dict = self.clients_to_lod(self._resp, self.ds_id)
            self.client_lod.append(self.client_dict)
        return self.client_lod

    def clients_to_lod(self, clients, ds_id):
        """
        Parse key fields from 'DS_GETDSCLIENTLIST'.
        Return clients as list of dicts
        """
        self._clients = clients
        self._ds_id = ds_id

        self._clients_io = StringIO(self._clients)
        self._clients_csv = csv.reader(self._clients_io, delimiter=',')

        self._parsed_clients = []
        for self._row in self._clients_csv:
            if len(self._row) < 2:
                continue
            if self._row[2] == "3":
                self._row.pop(0)
                self._row.pop(0)

            self._ds_fields = {'_dev_type': "0",
                              'name': self._row[1],
                              'id': self._row[0],
                              'enabled': self._row[2],
                              'ds_ip': self._row[3],
                              'hostname' : self._row[4],
                              'type_id': self._row[5],
                              'vendor': self._row[6],
                              'model': self._row[7],
                              'tz_id': self._row[8],
                              'date_order': self._row[9],
                              'port': self._row[11],
                              'syslog_tls': self._row[12],
                              'client_groups': "0",
                              'parent_id': self._ds_id
                              }
            self._parsed_clients.append(self._ds_fields)
        return self._parsed_clients

    def get_parent_datasources(self, ds_summary):
        """
        Parse dict for parent datasources
        Returns dict
        """
        self.ds_summary = ds_summary
        self.ds_parents = []
        for self.ds in self.ds_summary:
            if self.ds['_dev_type'] == "3" and int(self.ds['client_groups']) > 0:
                self.ds_parents.append(self.ds)
        return self.ds_parents

    def find_client_group(self, group_id):
        """
        Finds client group
        
        Args:
            DSID (str): Parent datasource ID set to self._ds_id
        
        Returns:
            Response dict with FTOKEN required for next step: 
        
        """
        self.group_id = group_id
        self._method, self._data = self.get_params('find_client_group')
        self._resp = self.post(self._method, self._data)
        return self._resp

    def get_file(self, ftoken):
        """
        Exchanges token for file
        
        Args:
            ftoken (str): instance name set by 
        
        """
        self.ftoken = ftoken
        self._method, self._data = self.get_params('get_file')
        self._resp = self.post(self._method, self._data)
        self._resp = dehexify(self._resp['DATA'])
        return self._resp

    def _add_venmods(self, devtree_lod):
        """
        Populates vendor/model fields for any datasources 
        """
        self._devtree_lod = devtree_lod
        for self._ds in self._devtree_lod:
            if not self._ds['vendor'] and self._ds['_dev_type'] == '3':
                (self._ds['vendor'], 
                self._ds['model']) = self._esm.type_id_to_venmod(self._ds['type_id'])
        return self._devtree_lod
    
    def _add_parent_ids(self, devtree_lod):
        """
        """
        self._devtree_lod = devtree_lod
        for self._ds in self._devtree_lod:
            if self._ds['_dev_type'] == "2":
                self._pid = self._ds['ds_id']
            if self._pid:
                self._ds['parent_id'] = self._pid
        return self._devtree_lod

                
class DataSource(Base):
    """
    A DataSource object represents a validated datasource configuration.
    This object represents current datasources as well as new datasources 
    to be added to the tree. 
    
    The kwargs required to initialize this class are detailed in __init__.
    """
    
    def __init__(self, dsconf):
        """
        Inits the datasource
        
        Args: 
            dsconf (dict of str: str)
            
            The dict may hold any number of valid datasource args, 
            but at a mininum, the following arguments are required:
            
            name (str): datasource name
            type_id (str): datasource type_id
            parent_id (str): datasource parent_id
            ip (str): unique IP address of datasource OR
            hostname (str): unique hostname 
            **kwargs: optional props
            
            Note:
            Both hostname and ip can be set, but at least one of them
            must be set.
            
        """
        super().__init__()
        if Base._baseurl == None:
            raise ESMException('ESM URL not set. Are you logged in?')
        self._esm = ESM()
        self._devtree = DevTree()
        self._ds_conf = dsconf
        self.ds_id = None
        self.child_enabled = "false"
        self.child_count = "0"
        self.child_type = "0"
        self.zone_id = "0"
        self.url = None
        self.enabled = 'true'
        self.idm_id = "0"
        self.hostname = None
        self.tz_id = None
        self.dorder = None
        self.maskflag = None
        self.port = None
        self.syslog_tls = None
        self.vendor = None
        self.model = None
        self.client_groups = None
        self.__dict__.update(self._ds_conf)
        self._prop = None
        self._pval = None

    def delete(self):
        """
        Deletes a datasource
        
        Args:
            ds_id (str). DataSource ID
            rec_id (str). Receiver ID / DataSource parent_id
            
        Warning:
            This really does delete the datasource and ALL data
            ever collected for that datasource.
        
        Returns:
            None
        
        Raises:
            ESMException: If the datasource to be deleted is 
                still in the tree after being deleted an Exception 
                will be raised.
        """
        print(self._ds_details())
        self._method, self._data = self.get_params('del_ds')
        self._resp = self.post(self._method, self._data)
        try:
            self._ds_details()
        except ESMDataSourceNotFound:
            print("WOWOWWOWA")
        
    def _ds_details(self):
        """
        Queries the ESM for datasource details
        
        Returns:
            dict (str, str) with some subdicts 
        
        Warning:
            Don't create a situation where this gets called for every
            datasource as it will not scale.
        """
        self._method, self._data = self.get_params('ds_details')
        return self.post(self._method, self._data)
        
            
    def add(self, client=False):
        """
        Adds a datasource
        
        Returns:
            None 
        
        Raises:
            ESMException: Will be raised if trying to add a duplicate datasource.
            
        """
        
        if self._devtree.search(self.name, zone_id=self.zone_id):
            raise ESMException('Datasource name already exists. '
                                'Cannot add datasource: {}'.format(self.name))
        if self._devtree.search(self.ds_ip, zone_id=self.zone_id):
            raise ESMException('Datasource IP already exists.' 
                                'Cannot add datasource: {}'.format(self.name))
            
        if client:
            self._method, self._data = self.get_params('add_client')
        else:
            self._method, self._data = self.get_params('add_parent')
        self._resp = self.post(self._method, self._data)
        self.parent_id = self._resp.get('id')
                                     
    def __repr__(self):
        """
        Dumps the datasource settings in json
        
        Returns:
            str: Datasource attributes as JSON
        """        
        return json.dumps(self.props())
    
    def props(self):
        """
        Dumps the datasource settings
        
        Returns:
            str: Datasource attributes as JSON
        """        
        return {self._prop: self._pval
            for self._prop, self._pval in self.__dict__.items()
            if not self._prop.startswith('_')}


    @staticmethod
    def valid_ip(ipaddr):
        """
        Validates IPv4/v6 address or raises ValueError.

        Args:
            ipaddr (str): IP address

        Returns:
            True if valid, False if not.
            
        Raises:
            ValueError: It's the wrong value if it's not valid.
        """
        try:
            ipaddr = str(ipaddress.ip_address(ipaddr))
            return True
        except ValueError:
            return False
