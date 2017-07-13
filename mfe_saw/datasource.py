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

try:
    from mfe_saw.base import Base
    from mfe_saw.utils import dehexify
    from mfe_saw.exceptions import ESMException
except ImportError:
    from base import Base
    from utils import dehexify
    from exceptions import ESMException

class DevTree(Base):
    """
    Interface to the ESM device tree.
    """
    def __init__(self, scope=None):
        """Coordinates assembly of the devtree"""
        super().__init__()
        if Base._baseurl == None:
            raise ESMException('ESM URL not set. Are you logged in?')
        self.scope = scope
        self.devtree = self.get_devtree()
        self.devtree = self.devtree_to_lod(self.devtree)
        self.parent_datasources = self.get_parent_datasources(self.devtree)
        self.clients = self.get_client_groups()
        self.clients = list(chain.from_iterable(self.clients))
        self.devtree = list(chain(self.devtree, self.clients))
        
    def __iter__(self):
        """
        Returns:
            Generator with datasource objects.
        """
        for self.ds in self.devtree:
            yield self.ds

    def __contains__(self, term):
        """
        Returns:
            bool: True/False the name or IP matches the provided search term.
        """
        self.term = term
        if self.search(term, inc_hostname=True):
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
            Datasource object that matches the provided search term.
            
        Raises:
            DupDataSource: Yes, it is possible for the search to return multiple 
            datasources when there are multple matches. 
            
            It is possible that there is a datasource name that matches a 
            hostname for a different datasource. This is generally an undesirable 
            state and should be corrected.
            
            The other possibility is that there are duplicate names, IP's, 
            hostnames across zones. If zones are being used then the zone 
            arg should also be used.
            
        """
        self.term = term
        self.inc_hostname = inc_hostname

        self.search_fields = ['ds_ip', 'name']
        if self.inc_hostname:
            self.search_fields.append('hostname')
        
        self.found = [ds for field in self.search_fields
                      for ds in self.devtree if ds[field].lower() == term.lower()]
                    
        if self.found:
            return self.found[0]

    def get_devtree(self):
        """
        Returns:
            ESM device tree; raw, but ordered, string in need of parsing.
            Does not include client datasources.
        """
        self.method, self.data = self.get_params(sys._getframe().f_code.co_name)
        self.callback = self.devtree_cb
        self.resp = self.post(self.method, self.data, self.callback)
        return self.resp

    def devtree_cb(self, resp):
        """
        get_devtree callback to format results
        
        Args:
            Requests response dict with an ITEMS key
        
        Returns:
            Cleaned up string of the same ready for 'dictification'
        """
        self.resp = resp
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
                              'client_groups': self.row[29],
                              '_cnt': self.row[3]
                              }
            self.parsed_datasources.append(self.ds_fields)
        return self.parsed_datasources

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
        for self.parent in self.parent_datasources:
            self.ds_id = self.parent['ds_id']
            self.resp = self.find_client_group(self.ds_id)
            self.ftoken = self.resp['FTOKEN']
            self.resp = self.get_file(self.ftoken)
            self.client_dict = self.clients_to_lod(self.resp, self.ds_id)
            self.client_lod.append(self.client_dict)
        return self.client_lod


    def clients_to_lod(self, clients, ds_id):
        """
        Parse key fields from 'DS_GETDSCLIENTLIST'.
        Return clients as list of dicts
        """
        self.clients = clients
        self.ds_id = ds_id
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
                              'client_groups': "0",
                              'parent_id': self.ds_id
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
        
        Args:
            DSID (str): Parent datasource ID set to self._ds_id
        
        Returns:
            Response dict with FTOKEN required for next step: 
        
        """
        self.group_id = group_id
        self.method, self.data = self.get_params(sys._getframe().f_code.co_name)
        self.resp = self.post(self.method, self.data)
        return self.resp

    def get_file(self, ftoken):
        """
        Exchange token for file
        
        Args:
            ftoken (str): instance name set by 
        
        """
        self.ftoken = ftoken
        self.method, self.data = self.get_params(sys._getframe().f_code.co_name)
        self.resp = self.post(self.method, self.data)
        self.resp = dehexify(self.resp['DATA'])
        return self.resp
    
    def add(self, ds_obj):
        """
        Adds a datasource
        
        """
        self.datasource = ds_obj
        from operator import itemgetter
        self.ordered = (sorted(self.devtree2, key=lambda x: int(itemgetter('_cnt')(x))))
                                               
#        for self.x in self.ordered:
#            print(self.x)
        

class DataSource(Base):
    """
    A DataSource object represents a validated datasource configuration.
    This object represents current datasources as well as new datasources 
    to be added to the tree. 
    
    There are some key fields required to interact with the native API so 
    this class ensures they are represented accurately. 
        
    """
    
    def __init__(self, dsconf):
        """This inits the datasource
    
        """
        super().__init__()
        if Base._baseurl == None:
            raise ESMException('ESM URL not set. Are you logged in?')    
        self._ds_conf = dsconf
        self.__dict__.update(self._ds_conf)
        self._var_d = vars(self).copy()


    def __repr__(self):
        return json.dumps({self._key: self._val 
                for self._key, self._val in self._var_d.items() 
                if not self._key.startswith('_')})


    def edit(self, field):
        self._field = field
        self._edit_fields = ['name', 'ip', 'hostname', 'zone_id', 'url', 
                             'enabled', 'tz_id', 'autolearn']

        if self._field not in self._edit_fields:
            raise ValueError("Field is read only.")

        if self._field not in self._edit_fields:
            raise ValueError("Field is read only.")
        