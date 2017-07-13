# -*- coding: utf-8 -*-
"""
    mfe_saw ESM Class

"""
import json

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
            host: str: IP or hostname of ESM.

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

        self._buildstamp = json.loads(self.post("essmgtGetBuildStamp").text)
        self._buildstamp = self._buildstamp['return']['buildStamp'].split(' ')
        return self._buildstamp

    def buildstamp(self):
        """
        Returns:
            str. ESM buildstamp.

        Example:
            '10.0.2 20170516001031'
        """
        return self.version()

    def time(self):
        """
        Returns:
            str. ESM time (GMT).

        Example:
            '2017-07-06T12:21:59.0+0000'
        """
        self._esmtime = json.loads(self.post("essmgtGetESSTime").text)
        return self._esmtime['return']['value']

    def etime(self):
        """
        Returns:
            str. ESM epoch time.

        Example:
            '1499351686'
        """
        self._esmtime = json.loads(self.post("essmgtGetESSTime").text)
        return self._esmtime['return']['value']

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

        """
        return self.post("sysGetSysInfo").json()['return']

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

    def timezones(self):
        """
        """
        self.post('userGetTimeZones')
    