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
from functools import partial

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

class DataSource(Base):
    """
    A DataSource object represents a validated datasource configuration.
    
    This object represents current datasources as well and acts as a 
    validation template for new datasources 
    
    Public Methods:
        add()       Adds the datasource object to the ESM.
        
        edit()      Edits a datasource parameter - Not yet implemented.
        
        delete()    Deletes the datasource and ALL associated data.
        
        props()     Returns a JSON string of datasource properties.
        
        __len__     Returns the number of properties set.
        
        __repr__    Print the datasource, returns props()
        
    """

    def __len__(self):
        """
        Count up the datasource attributes
        
        Returns:
            int: Number of DataSource attributes set
        """
        return len(self.props())
            
    def __repr__(self):
        """
        Dumps the datasource settings in json
        
        Returns:
            str: Datasource attributes as JSON
        """        
        return json.dumps(self.props())
    
    def __init__(self, **kwargs):
        """
        Inits the datasource
        
        Args: 
            kwargs:
            
                Can represent any valid datasource attribute, but at 
                a mininum, the following arguments are required to 
                init the object:
            
                name (str): datasource name
                type_id (str): datasource type_id
                parent_id (str): datasource parent_id
                ds_ip (str): unique IP address of datasource*
                hostname (str): unique hostname*
                
                + Any additional valid params...
                            
            Note:
            * Both hostname and ip can be set, but at least one of them
              MUST be set.
            
        """
        
        super().__init__()
        if Base._baseurl == None:
            raise ESMException('ESM URL not set. Are you logged in?')
        self._kwargs = kwargs
        
        self._esm = ESM()
        self._devtree = DevTree()

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
        self._prop = None
        self._pval = None
        self.__dict__.update(self._kwargs)
        
        self._dsfields = ['parent_id', 'name','ds_id', 'type_id', 'rec_ip',
                           'child_enabled', 'child_count', 'child_type',
                           'ds_ip', 'zone_id', 'url', 'enabled', 'idm_id']

        self.parameters = [{self._key: self._val 
                            for self._key, self._val in self._kwargs.items()
                            if self._key not in self._dsfields}]

    def _validate_name(self, name):
        """
        Returns:
            None
        
        Raises:
            KeyError: if name is missing or invalid
        """
        try:
            if re.search('^[a-zA-Z0-9_-]{1,100}$', self.name):
                pass
            else:
                raise KeyError('Valid name required for DataSource')
        except KeyError:
            raise KeyError('Valid name required for DataSource')
    
    def props(self):
        """
        Dumps the datasource settings
        
        Returns:
            str: Datasource attributes as JSON
        """        
        return {self._prop: self._pval
            for self._prop, self._pval in self.__dict__.items()
            if not self._prop.startswith('_')}
                
                    
    def add(self, client=False):
        """
        Adds a datasource
        
        Returns:
            None 
        
        Raises:
            ESMException: Will be raised if trying to add a duplicate
            datasource or if something else goes wrong.
        """
        self._search_dups = partial(self._devtree.search, rec_id=self.parent_id)
        if self._search_dups(self.name, zone_id=self.zone_id):
            raise ESMException('Datasource name already exists.'
                                'Cannot add datasource: {}'.format(self.name))
        if self._search_dups(self.ds_ip, zone_id=self.zone_id):
            raise ESMException('Datasource IP already exists.' 
                                'Cannot add datasource: {}'.format(self.ds_ip))
        if client:
            self._method, self._data = self._get_params('add_client')
        else:
            self._method, self._data = self._get_params('add_ds')
        self._resp = self.post(self._method, self._data)

        if client:
            try:
                self._err_code = self._resp['EC']
                if self._err_code == '0':
                    return None
            except KeyError:
                raise ESMException('Unexpected error occured. ' 
                                    'DS may not have been added.')
        try:
            self._ds_id = self._resp.get('id')
            return None
        except (KeyError, AttributeError):
            pass
        
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
        self._method, self._data = self._get_params('del_ds')
        self._resp = self.post(self._method, self._data)
        
    def _ds_details(self):
        """
        Queries the ESM for datasource details
        
        Returns:
            dict (str, str) with some subdicts 
        
        Warning:
            Don't create a situation where this gets called for every
            datasource as it will not scale.
        """
        self._method, self._data = self._get_params('ds_details')
        return self.post(self._method, self._data)
            
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
            
            
class DevTree(Base):
    """
    Interface to the ESM device tree.
    
    Public Methods:
    
        search('term')      Returns a DataSource object matching the name,
                        IPv4/IPv6 address, hostname or device ID.

        search_group(field='term')    Returns a list of DataSource objects that match 
                                  the given term for the given field. 
                                  Valid field options include:
                                    - parent_id = '144119615532826624'
                                    - type_id = '65'
                                    - vendor = 'Intersect Alliance'
                                    - model = 'Snare for Windows'
                                    - syslog_tls = 'T'
                                    - port = '514'
                                    - tz_id = '51'
                                    - tz_name = 'Darwin'
                                    - zone_id = '7'
                                    
        steptree()  Returns an ordered list of lists representing the 
                       default 'Physical Display' device tree on the ESM.
                       This is useful to recreate a graphical representation
                       of the device tree.
                    
                       Inner list fields: [tree_id, ds_name, ds_ip, depth]

                       tree_id: The order in which the datasource 
                                 appears in the ESM 'Physical Display'
                                 
                       name:   Datasource name
                        
                       IP:     Datasource IP
                        
                       depth:  1 = ESM
                                2 = ERC/ADM/DEM/ACE/ELM/ELS
                                3 = Datasources including EPO/NSM
                                4 = Children and Clients
                        
        last_times('time')    Returns a list of DataSource objects that 
                                 the ESM has NOT heard from since the 
                                 provided timeframe.
                                
                                If no time is given, the default is LAST_24_HOURS
                                
                                Other valid timeframe keywords are:
                                - LAST_MINUTE
                                - LAST_10_MINUTES
                                - LAST_30_MINUTES
                                - LAST_HOUR
                                - CURRENT_DAY
                                - PREVIOUS_DAY
                                - LAST_24_HOURS
                                - LAST_2_DAYS
                                - LAST_3_DAYS
                                - LAST_30_DAYS
                                - LAST_60_DAYS
                                - LAST_90_DAYS
                                - LAST_180_DAYS
                                - CURRENT_WEEK
                                - PREVIOUS_WEEK
                                - CURRENT_MONTH
                                - PREVIOUS_MONTH
                                - CURRENT_QUARTER
                                - PREVIOUS_QUARTER
                                - CURRENT_YEAR
                                - PREVIOUS_YEAR

        refresh()   Rebuilds the tree
                            
        __len__     Returns the total number of devices in the tree
        
        __iter__    Interates through each DataSource object in the tree. 
        
        __contains__    Returns bool as to whether a datasource name, IP,
                        hostname or ds_id exist in the device tree.
                        
    """
    _DevTree = []

    def __init__(self):
        """
        Initalize the DevTree object
        """
        super().__init__()
        if Base._baseurl == None:
            raise ESMException('ESM URL not set. Are you logged in?')
        self._esm = ESM()    
        if not DevTree._DevTree:
            self._build_devtree()

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
        self._ds_desc_ids = ['3', '256']
        for self._ds in DevTree._DevTree:
            if self._ds['desc_id'] in self._ds_desc_ids:
                yield DataSource(**self._ds)

    def __contains__(self, term):
        """
        Returns:
            bool: True/False the name or IP matches the provided search term.
        """
        self._cterm = term
        if self._ds(self._cterm):
            return True
        else:
            return None
            
    def search(self, term, rec_id=None, zone_id='0'):
        """
        Args:
            term (str): Datasource name, IP, hostname or ds_id
            
            zone_id (int): Provide zone_id to limit search to a specific zone

        Returns:
            Datasource object that matches the provided search term or None.

        """
        self._term = term.lower()
        self._rec_id = rec_id
        self._zone_id = zone_id

        self._search_fields = ['ds_ip', 'name', 'hostname', 'ds_id']

        self._found = [self._ds for self._ds in DevTree._DevTree 
                            for self._field in self._search_fields 
                            if self._ds[self._field].lower() == self._term 
                            if self._ds['zone_id'] == self._zone_id]

        if self._rec_id and len(self._found) > 1:
            self._found = [self._ds for self._ds in self._found 
                            if self._ds['parent_id'] == self._rec_id]
        
        if self._found:
            return DataSource(**self._found[0])
        else:
            return None

    def search_ds_group(self, field, term, zone_id='0'):
        """
        Args:
            field (str): Valid DS config field to search
            term (str): Data to search for in specified field
            
        Returns:
            Generator containing any matching DataSource objects or None
            Result must be iterated through.
            
        Raises:
            ValueError: if field or term are None
        """
        self._field = field
        self._term = term
        self._zone_id = zone_id
        
        if not self._field:
            raise ValueError('DataSource field required')

        if not self._term:
            raise ValueError('DataSource field value required')

        return (DataSource(self._ds) for self._ds in DevTree._DevTree
                        if self._ds.get(self._field) == self._term)
                       
    def steptree(self):
        """
        Summarizes the devtree into names and IPs. 
        
        Includes depth count to indicate how many steps from the root 
        of the tree the device would be if this data were presented 
        graphically. 
        
        Also includes parent_id as another method to group datasources 
        under another device.
        
        Returns:
            List of tuples (int,str,str,str) (step, name, ip, parent_id)        
        """
        for self._ds in DevTree._DevTree:
            self._step = (self._ds['idx'], self._ds['name'], self._ds['ds_ip'], 
                            self._ds['parent_id'],)
            print(self._step)
                    
    def refresh(self):
        """
        Rebuilds the devtree
        """
        self._build_devtree()
        
    def get_ds_times(self):
        """
        """
        self._last_times = self._get_last_event_times()
        self._insert_ds_last_times(self._last_times)
        
    def recs(self):
        """
        Returns:
            list of Receiver dicts (str:str)
        """
        return [self._rec for self._rec in DevTree._DevTree 
                    if self._rec['desc_id'] == '2']
    
    def _get_last_event_times(self):
        """
        
        Returns:
                    
        """
        self._method, self._data = self._get_params('ds_last_times')
        self._resp = self.post(self._method, self._data)
        return dehexify(self._resp['ITEMS'])

    def _insert_ds_last_times(self, last_times_str):
        """
        Parse event times str and insert it into the _devtree
        
        Returns: 
            List of datasource dicts - the devtree
        """
        self._last_times_io = StringIO(last_times_str)
        self._last_times_csv = csv.reader(self._devtree_io, delimiter=',')
        self._last_times_lod = []
        for self._row in self._last_times_csv:
            if len(self._row) == 0:
                continue

    def _build_devtree(self):
        """
        Coordinates assembly of the devtree object
        """
        self._devtree = self._get_devtree()
        self._devtree = self._devtree_to_lod()
        self._devtree = self._insert_parent_ids()
        self._client_containers = self._get_client_containers()

        """
        This next bit of code gets and formats the clients for each
        container and inserts them back into the devtree.
        
        The tricky part is keeping the devtree in order and keeping 
        index labels consistent for all of the devices while 
        inserting new devices into the middle with their own index
        labels. Kind of like changing a tire on a moving car...
        
        pidx - parent idx is the original index value of the parent
                this does not increment
                
        cidx - client idx is incremented starting after the pidx
        
        didx - stores the delta between different containers to 
               keep it all in sync.
        """
        self._cidx = 0
        self._didx = 0
        for self._container in self._client_containers:
            self._raw_clients = self._get_raw_clients(self._container['ds_id'])
            self._clients_lod = self._clients_to_lod(self._raw_clients)
            self._container['idx'] = self._container['idx'] + self._didx
            self._pidx = self._container['idx']
            self._cidx = self._pidx + 1 
            for self._client in self._clients_lod:
                self._client['parent_id'] = self._container['ds_id']
                self._client['idx'] = self._cidx 
                self._cidx += 1 
                self._didx += 1
            self._devtree[self._pidx:self._pidx] = self._clients_lod 
            
        self._zonetree = self._get_zonetree()
        self._devtree = self._insert_zone_names()
        self._zone_map = self._get_zone_map()
        self._devtree = self._insert_zone_ids()            
        self._devtree = self._insert_venmods()
        self._devtree = self._insert_desc_names()
        DevTree._DevTree = self._devtree
               
    def _get_devtree(self):
        """
        Returns:
            ESM device tree; raw, but ordered, string.
            Does not include client datasources.
        """
        self._method, self._data = self._get_params('get_devtree')
        self._resp = self.post(self._method, self._data)
        return dehexify(self._resp['ITEMS'])

    def _devtree_to_lod(self):
        """
        Parse key fields from raw device strings into datasource dicts
        
        Returns: 
            List of datasource dicts
        """
        self._devtree_io = StringIO(self._devtree)
        self._devtree_csv = csv.reader(self._devtree_io, delimiter=',')
        self._devtree_lod = []

        for self._idx, self._row in enumerate(self._devtree_csv, start=1):
            if len(self._row) == 0:
                continue
            
            if self._row[0] == '16':  # Get rid of duplicate 'asset' devices
                continue
            
            if self._row[2] == "3":  # Client group datasource group containers
                self._row.pop(0)     # are fake datasources that seemingly have
                self._row.pop(0)     # two uneeded fields at the beginning.

            if self._row[16] == 'TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT':
                self._row[16] = '0'  # Get rid of weird type-id for N/A devices
                
            self._ds_fields = {'idx': self._idx,
                                'desc_id': self._row[0],
                                'name': self._row[1],
                                'ds_id': self._row[2],
                                'enabled': self._row[15],
                                'ds_ip': self._row[27],
                                'hostname' : self._row[28],
                                'type_id': self._row[16],
                                'vendor': '',
                                'model': '',
                                'tz_id': '',
                                'date_order': '',
                                'port': '',
                                'syslog_tls': '',
                                'client_groups': self._row[29],
                                'zone_name': '',
                                'zone_id': '',
                                'client': False
                              }
            self._devtree_lod.append(self._ds_fields)
        return self._devtree_lod

    def _insert_parent_ids(self):
        """
        Adds parent_ids to datasources in the tree based upon the 
        ordered list provided by the ESM. All the datasources below
        a Receiver row have it's id set as their parent ID.
        
        Returns:
            List of datasource dicts
        """
        self._pid = '0'
        for self._ds in self._devtree:
            if self._ds['desc_id'] == '2':
                self._pid = self._ds['ds_id']

            if self._ds['desc_id'] == '3':
                self._ds['parent_id'] = self._pid
        return self._devtree

    def _get_client_containers(self):
        """
        Filters DevTree for datasources that have client datasources.
        
        Returns:
            List of datasource dicts that have clients
        """
        return [self._ds for self._ds in self._devtree
                                if self._ds['desc_id'] == "3" 
                                if int(self._ds['client_groups']) > 0]
        
    def _get_raw_clients(self, ds_id):
        """
        Get list of raw client strings.
        
        Args:
            ds_id (str): Parent ds_id(s) are collected on init
            ftoken (str): Set and used after requesting clients for ds_id
            
        Returns:
            List of strings representing unparsed client datasources
        """
        self._ds_id = ds_id
        self._method, self._data = self._get_params('req_client_str')
        self._resp = self.post(self._method, self._data)

        self._ftoken = self._resp['FTOKEN']
        return self._get_file(self._ftoken)

    def _get_client_list(self, group_id):
        """
        Finds client group
        
        Args:
            DSID (str): Parent datasource ID set to self._ds_id
        
        Returns:
            Response dict with FTOKEN required to get the data file
        
        """
        self.group_id = group_id
        self._method, self._data = self._get_params('req_client_str')
        self._resp = self.post(self._method, self._data)
        return self._resp

    def _get_file(self, ftoken):
        """
        Exchanges token for file
        
        Args:
            ftoken (str): instance name set by 
        
        """
        self.ftoken = ftoken
        self._method, self._data = self._get_params('get_rfile')
        self._resp = self.post(self._method, self._data)
        self._resp = dehexify(self._resp['DATA'])
        return self._resp

    def _clients_to_lod(self, clients):
        """
        Parse key fields from _get_clients() output.
        
        Returns:
            list of dicts
        """
        self._clients = clients

        self._clients_io = StringIO(self._clients)
        self._clients_csv = csv.reader(self._clients_io, delimiter=',')

        self._clients_lod = []
        for self._row in self._clients_csv:
            if len(self._row) < 2:
                continue

            self._ds_fields = {'desc_id': "256",
                              'name': self._row[1],
                              'ds_id': self._row[0],
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
                              'zone_name': '',
                              'zone_id': '',
                              'client': True
                              }
            self._clients_lod.append(self._ds_fields)
        return self._clients_lod
            
    def _get_zonetree(self):
        """
        Abuses the device tree for zone data.
        
        Returns:
            str: device tree string sorted by zones
        """
        
        self._method, self._data = self._get_params('get_zones_devtree')
        self._resp = self.post(self._method, self._data)
        return dehexify(self._resp['ITEMS'])
        
    def _insert_zone_names(self):
        """
        Args:
            _zonetree (str): set in __init__
        
        Returns:
            List of dicts (str: str) devices by zone
        """
        self._zone_name = None
        self._zonetree_io = StringIO(self._zonetree)
        self._zonetree_csv = csv.reader(self._zonetree_io, delimiter=',')
        self._zonetree_lod = []

        for self._row in self._zonetree_csv:
            if self._row[0] == '1':
                self._zone_name = self._row[1]
                if self._zone_name == 'Undefined':
                    self._zone_name = ''
                continue
            for self._dev in self._devtree:
                if self._dev['ds_id'] == self._row[2]:
                    self._dev['zone_name'] = self._zone_name
        return self._devtree

    def _get_zone_map(self):
        """
        Builds a table of zone names to zone ids.
        
        Returns:
            dict (str: str) zone name : zone ids
        """
        self._zone_map = {}
        self._method, self._data = self._get_params('zonetree')
        self._resp = self.post(self._method, self._data)
        for self._zone in self._resp:
            self._zone_map[self._zone['name']] = self._zone['id']['value']
            for self._szone in self._zone['subZones']:
                self._zone_map[self._szone['name']] = self._szone['id']['value']
        return self._zone_map
        
    def _insert_zone_ids(self):
        """
        """
        for self._dev in self._devtree:
            if self._dev['zone_name'] in self._zone_map.keys():
                self._dev['zone_id'] = self._zone_map.get(self._dev['zone_name'])
            else:
                self._dev['zone_id'] = '0'
        return self._devtree
        
    def _insert_venmods(self):
        """
        Populates vendor/model fields for any datasources 
        
        Returns:
            List of datasource dicts - devtree
        """
        for self._ds in self._devtree:
            if not self._ds['vendor'] and self._ds['desc_id'] == '3': 
                self._ds['vendor'], self._ds['model'] = self._esm.type_id_to_venmod(self._ds['type_id'])
        return self._devtree_lod
    
    def _insert_desc_names(self):
        """
        Populates the devtree with desc_names matching the desc_ids
        
        Returns:
            List of datasource dicts - devtree
        
        """
        self._meth, self._type_map = self._get_params('_dev_types')
        for self._ds in self._devtree:
            if self._ds['desc_id'] in self._type_map:
                self._ds['desc'] = self._type_map[self._ds['desc_id']]
        return self._devtree
        
    def _get_client_grps(self):
        """
        Returns:
            dict (str:str) fake datasource dicts that represent client 
            containers on the device tree.
        """
        return [self._dev for self._dev in DevTree._DevTree 
                        if int(self._dev['client_groups']) > 0 
                        and self._dev['desc_id'] == '3']
