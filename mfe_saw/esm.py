# -*- coding: utf-8 -*-
"""
    mfe_saw ESM Class

"""
import json
from functools import lru_cache

try:
    from mfe_saw.base import Base
except ImportError:
    from base import Base

class ESM(Base):
    """
    ESM class
    """
    def __init__(self):
        """
        Args:
            host (str): IP or hostname of ESM.

        Returns:
            obj. ESM object
        """
        super().__init__()

    def version(self):
        """
        Returns:
            str. ESM short version.

        Example:
            '10.0.2'
        """
        return self.buildstamp().split()[0]

    def buildstamp(self):
        """
        Returns:
            str. ESM buildstamp.

        Example:
            '10.0.2 20170516001031'
        """
        return self.post('essmgtGetBuildStamp')['buildStamp']

    def time(self):
        """
        Returns:
            str. ESM time (GMT).

        Example:
            '2017-07-06T12:21:59.0+0000'
        """
        self._esmtime = self.post("essmgtGetESSTime")
        return self._esmtime['value']


    def status(self):
        """
        Returns:
            dict. ESM stats.
            including:
                - processor status
                - hdd status
                - ram status
                - rule update status
                - backup status
                - list of top level devices
        Other functions exist to return subsets of this data also.
        """
        return self.post("sysGetSysInfo")

    def disks(self):
        """
        Returns:
            str. ESM disks and utilization.

        Example:
            'sda3     Size:  491GB, Used:   55GB(12%), Available:  413GB, Mount: /'
        """
        return self.status()['hdd']

    def ram(self):
        """
        Returns:
            str. ESM ram and utilization.

        Example:
            'Avail: 7977MB, Used: 7857MB, Free: 119MB'
        """
        return self.status()['ram']

    def backup_status(self):
        """
        Returns:
            dict. Backup status and timestamps.

        Example:
            {'autoBackupEnabled': True,
                'autoBackupDay': 7,
                'autoBackupHour': 0,
                'backupLastTime': '07/03/2017 08:59:36',
                'backupNextTime': '07/10/2017 08:59'}
        """
        self._fields = ['autoBackupEnabled',
                        'autoBackupDay',
                        'autoBackupHour',
                        'autoBackupHour',
                        'backupNextTime']

        return {self.key: self.val for self.key, self.val in self.status().items()
                if self.key in self._fields}

    def callhome(self):
        """
        Returns:
            bool. True/False if there is currently a callhome connection
        """
        self._callhome_ip = self.status()['callHomeIp']
        if self._callhome_ip:
            return True

    def rules_status(self):
        """
        Returns:
            dict. Rules autocheck status and timestamps.

        Example:
        { 'rulesAndSoftwareCheckEnabled': True
          'rulesAndSoftLastCheck': '07/06/2017 10:28:43',
          'rulesAndSoftNextCheck': '07/06/2017 22:28:43',}

        """
        self._fields = ['rulesAndSoftwareCheckEnabled',
                        'rulesAndSoftLastCheck',
                        'rulesAndSoftNextCheck']
        return {self.key: self.val for self.key, self.val in self.status().items()
                if self.key in self._fields}

    @lru_cache(maxsize=None)   
    def _get_timezones(self):
        """
        Gets list of timezones from the ESM.
        
        Returns:
            str. Raw return string from ESM including 
        """
        return self.post('userGetTimeZones')

        
    def tz_offsets(self):
        """
        Builds table of ESM timezones including offsets.
        
        Returns:
            list. List of timezone tuples (name, id, offset)
            
        Example:
            [(1, 'Midway Island, Samoa', '-11:00'),
             (2, 'Hawaii', '-10:00'),
             ...
            ]
        """
        self.tz_resp = self._get_timezones()
        return [(self.tz['id']['value'], self.tz['name'], self.tz['offset']) 
                  for self.tz in self.tz_resp]
                   
        
    def timezones(self):
        """
        Builds table of ESM timezones and names only. No offsets.
        
        Returns:
            dict. {timezone_id, timezone_name}
        """
        self.tz_resp = self._get_timezones()
        self.tz_table = {str(self.tz['id']['value']): self.tz['name']
                            for self.tz in self.tz_resp}
        return self.tz_table

    def tz_name_to_id(self, tz_name):
        """
        Args:
            tz_name (str): Case sensitive, exact match timezone name
            
        Returns:
            str. Timezone id or None if there is no match
        """
        self.tz_reverse = {self.tz_name: self.tz_id 
                            for self.tz_id, self.tz_name in self.timezones().items()}
        try:
            return self.tz_reverse[tz_name]
        except KeyError:
            return None
    
    def tz_id_to_name(self, tz_id):
        """
        Args:
            td_id (str): Numerical string (Currently 1-74)
        
        Returns:
            str. Timezone name or None if there is no match
        """
        try:
            return self.timezones()[tz_id]
        except KeyError:
            return None
    
    def type_id_to_venmod(self, type_id):
        """
        Args:
            type_id (str): Numerical string 
        
        Returns:
            tuple. (vendor, model) or None if there is no match
        """
        self.type_id = type_id
        self.ds_types = self._get_ds_types()
        for self.venmod in self.ds_types:
            if str(self.venmod[0]) == str(self.type_id):
                return (self.venmod[1], self.venmod[2])

    def venmod_to_type_id(self, vendor, model):
        """
        Args:
            vendor (str): Exact vendor string including puncuation
            model (str): Exact vendor string including puncuation
        
        Returns:
            str. Matching type_id or None if there is no match
        """
        self.vendor = vendor
        self.model = model
        self.ds_types = self._get_ds_types()
        for self.venmod in self.ds_types:
            if self.vendor == self.venmod[1]:
                if self.model == self.venmod[2]:
                    return str(self.venmod[0])
        
     
    @lru_cache(maxsize=None)   
    def _get_ds_types(self):
        """
        Retrieves device table from ESM
                    
        Returns:
            list. of tuples output from callback: _format_ds_types()

        Note:
            rec_id (str): self.rec_id assigned in method
        """
        self.rec_id = self.recs()[0][1]
        self.method, self.data = self._get_params('get_dstypes')
        self.venmods = self.post(self.method, self.data, self._format_ds_types)
        return self.venmods
                    
    def _format_ds_types(self, venmods):
        """
        Callback to create type_id/vendor/model table
        
        Args:
            venmods (obj): request object from _get_ds_types
        
        Returns:
            list. of tuples 
                
           [(542, 'McAfee', 'SaaS Email Protection')
            (326, 'McAfee', 'Web Gateway')
            (406, 'Microsoft', 'ACS - SQL Pull')
            (491, 'Microsoft', 'Endpoint Protection - SQL Pull')
            (348, 'Microsoft', 'Exchange')]

        Note: 
            This is a callback for _get_ds_types.

        """
        self._venmods = venmods
        return [(self._mod['id']['id'], self._ven['name'], self._mod['name'],)
                    for self._ven in self._venmods['vendors']
                    for self._mod in self._ven['models']]

    @lru_cache(maxsize=None)    
    def recs(self):
        """
        
        """
        self.method, self.data = self._get_params('get_recs')
        self._rec_list = self.post(self.method, self.data)
        return [(self._rec['name'], self._rec['id']['id']) 
                  for self._rec in self._rec_list]
