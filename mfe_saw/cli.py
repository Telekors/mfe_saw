# -*- coding: utf-8 -*-

"""Console script for mfe_saw"""

import argparse
import csv
import json
import os
import sys
from configparser import ConfigParser, NoSectionError, MissingSectionHeaderError
from pathlib import Path

from mfe_saw.esm import ESM 
from mfe_saw.exceptions import ESMException
from mfe_saw.datasource import DataSource, DevTree
from mfe_saw.version import __version__

    
def get_args(args):
    args = args
    log_levels = ['quiet', 'error', 'warning', 'info', 'debug']
    output_formats = ['json', 'csv', 'raw', 'word']
    
    formatter_class = argparse.RawDescriptionHelpFormatter
    
    parser = argparse.ArgumentParser(formatter_class=formatter_class,
                                          description='McAfee SIEM API Wrapper')
                                          
    parser.add_argument('-a', '--add', 
                             action='store_true', dest='add', default=None,
                             help='Scan <dsdir> for new datasource files')

                             
    parser.add_argument('-s', '--search', 
                             dest='search', nargs='?', default=None, metavar='term',
                             help='Search for datasource name, hostname, or IP.'
                                   'May require quotes around the name if there'
                                   'are spaces.')
    parser.add_argument('-v',
                             action='store_true', dest='esm_version', default=None,
                             help='Prints the software release version for the ESM.')
    
    parser.add_argument("--version", action="version", help="mfe_saw version",
                                 version="%(prog)s {}".format(__version__))
                             
    pargs = parser.parse_args()        
    return pargs

class Config(object):
    """
    Find the config settings which include:
    
     - esm_host
     - esm_user
     - esm_passwd    
    """
    CONFIG = None

    @classmethod
    def find_ini(cls):
        """
        Attempt to locate a mfe_saw.ini file 
        """
        config = ConfigParser()
        module_dir = os.path.dirname(sys.modules[__name__].__file__)

        if 'APPDATA' in os.environ:
            conf_path = os.environ['APPDATA']
        elif 'XDG_CONFIG_HOME' in os.environ:  
            conf_path = os.environ['XDG_CONFIG_HOME']
        elif 'HOME' in os.environ:  
            conf_path = os.path.join(os.environ['HOME'], '.config')
        else:
            conf_path = None

        paths = [os.path.join(module_dir, '.mfe_saw.ini'), '.mfe_saw.ini']
        if conf_path is not None:
            paths.insert(1, os.path.join(conf_path, '.mfe_saw.ini'))
        config.read(paths)
        cls.CONFIG = config

    def __init__(self, **kwargs):
        """
        Initialize a Config instance.
        
        """
        self._kwargs = kwargs
        self.find_ini()
        self._find_envs()
        self._init_config()
    
    def _find_envs(self):
        """
        Builds a dict with env variables set starting with 'ESM'.
        """
        self._envs = {self._kenv: self._venv 
                        for self._kenv, self._venv in os.environ.items()
                          if self._kenv.startswith('ESM')}
                          
    def _init_config(self):
        """ 
        """
        if not self.CONFIG:
            raise FileNotFoundError('mfe_ini file not found.')
            
        try:
            self.types = dict(self.CONFIG.items('types'))
        except NoSectionError:
            self.types = None
            
        try:
            self.recs = dict(self.CONFIG.items('recs'))
        except NoSectionError:
            self.recs = None

        try:
            self._ini = dict(self.CONFIG.items('esm'))
            self.__dict__.update(self._ini)
        except NoSectionError:
            print("Section [esm] not found in mfe_saw.ini")

        # any envs overwrite the ini values
        if self._envs:
            self._envs = {self._key.lower(): self._val
                            for self._key, self._val in self._envs.items()}
            self.__dict__.update(self._envs)

def verify_dir(dir):
    """
    Checks if a directory exists, if not, it creates it.
    
    Args:
        path (str): name of directory to check
    
    Returns:
        path object for directory
    
    Raises:
        OSError if unable to create the directory due to permissions
        or whatnot. 
    """
    path = Path(dir)

    if os.path.isdir(path):
        pass
    else: 
        try:
            os.makedir(path)
        except OSError:
            raise
    return path
    
def scan_dir(dir):
    """
    Args:
        dir (str): directory name to scan
    
    Returns:
        list of any files in dir or none
    """
    path = Path(dir)
    return [file for file in path.iterdir()]
     
def convert_ds_files(files, types=None):
    """
    Abstraction function between cli and file processing. 
    
    Checks given list of filenames to see if they are ini, 
    csv or otherwise. If so, routes them to appropriate
    conversion function.
    
    Args:
        filenames (list): list of filenames to convert         
   
    Returns:
        list of dicts - each represents a single datasource config            
    """
    ds_lods = []
    for file in files:
        ds_dict = ini_to_dict(file, 'datasource')
        if ds_dict:
            ds_lods.append(ds_dict)
        else:    
            csv_lod = csv_to_dict(file, types=types)
            if csv_lod:
                ds_lods.extend(csv_lod)
    return ds_lods

def csv_to_dict(file, types=None):
    """
    Attempts to convert csv file into dict. 
    
    First it's converted into a list of lists containing the rows.
    
    Validity is determined by the column count; valid datasource
    csv files will have 3 or more columns. 
    
    Optionally a types dict to look up type_id in the case of 
    legacy 3col format. See more info in process_3col_csv.
    
    Args:
        file (str): filename to convert
        types (dict): {type_id: file_str}
    Returns:
        list of lists from the CSV file or None on failure
        
    Raises:
        ValueError: if 3col datasource file detected without ini types
    """
    csv_lol = csv_to_lol(file)
    
    if not csv_lol:
        ds_dicts = None
    elif len(csv_lol[0]) < 3:
        ds_dicts = None
    elif len(csv_lol[0]) == 3:
        if not types:
            raise ValueError('DataSource file detected as 3col format'
                              'but missing [types] section from mfe_saw.ini')
        else:
            type_id = None
            filename = file.parts[-1]
            for id, file_str in types.items(): 
                if file_str in filename:
                    type_id = id
            ds_dicts = process_3col_csv(csv_lol, type_id)
    else:
        ds_dicts = process_export_csv(csv_lol)   
    return ds_dicts
 
def process_export_csv(lol):
    """
    Args:
        list of lists - converted datasource export file
    """
    headers, lol = get_csv_headers(lol)
    
    if not headers:
        return None
    
    for line in lol:
        ds_lod = [dict(zip(headers, line))]
    
    ds_lod = map_csv_fields(ds_lod)
    return ds_lod

def get_csv_headers(lol):
    """
    """
    if lol[0][0] == '#version#':
        headers = lol.pop(1)
    elif lol[0][0] == 'op':
        headers = lol.pop(0)
    else:
        return None
    return (headers, lol)

def map_csv_fields(ds_lod):
    for ds in ds_lod:
        enabled = 'true'
        if ds['parsing'] == 'no':
            enabled = 'false'
        ds_fields = {'op': ds.pop('op'),
                     'desc_id': '3',
                     'name': ds.pop('dsname'),
                     'ds_id': ds.pop('linked_ipsid'),
                     'enabled': enabled,
                     'ds_ip': ds.pop('ip'),
                     'hostname' : ds.pop('hostname'),
                     'type_id': '',
                     'vendor': ds.pop('vendor'),
                     'model': ds.pop('model'),
                     'tz_id': ds.pop('tz_id'),
                     'date_order': '',
                     'port': ds.pop('syslog_port'),
                     'syslog_tls': ds.pop('require_tls'),
                     'client_groups': '',
                     'zone_name': '',
                     'zone_id': ds.pop('zoneID'),
                     'client': False,
                     'parent_id': ds.pop('rec_id'),
                     'parameters': [ds]}

        for x, y in ds_fields.items():
            print(x, y)
    
def process_3col_csv(lol, type_id):
    """
    3 column format is a legacy format that allows for a ds config
    file in the format of:
    
        new-ds-name,new-ds-ip,rec-ip 
        
        linux_123,10.0.2.3,172.16.12.30
    
    This is dependant on creating a section in the ini file
    called [types] with file strings to types. For instance:
    
    65=linux
    166=nxlog
    
    type_ids can be looked up using this script, see help for flag
    
    the file string is a bit of text that will be in the filename.
    in the example above, any filenames with 'linux' included:
    - 123linux
    - newlinuxds
    - linuxbox234
    
    with the format above would be added as type_id: 65, or linux devices.
    
    Using the ini format is recommended.
    
    Args:
        filename (list) of csv rows as lists
    
    Returns:
        list of dicts 
    """
    ds_dicts = []
    for row in lol:
        ds_dicts.append({'name': row[0],
                         'ds_ip': row[1],
                         'rec_ip': row[2],
                         'type_id': type_id})
    return ds_dicts
    
def ini_to_dict(filename, subdict):
    """
    ini_to_dict() wrapper to extract subdict
    
    Args:
        filename (str): ini file to convert
        subdict (str): section in ini file / dict key 
    
    Returns:
        dict (str:str) key, val
     
    Note:
        Without this wrapper the result would be {key {k1:v1, k2:v2}}
        instead of flat {k1:v1, k2:v2}
        
    """
    ini_dict = _ini_to_dict(filename)
    
    try:
        return ini_dict.get(subdict)
    except AttributeError:
        pass
    
def _ini_to_dict(filename):
    """
    Returns:
        dict containing values of ini file or None if file is not valid
    """
    class INI_Parser(ConfigParser):
        def get_ini_dict(self):
            ini_dict = dict(self._sections)
            for key in ini_dict:
                ini_dict[key] = dict(self._defaults, **ini_dict[key])
                ini_dict[key].pop('__name__', None)
            return ini_dict
    parser = INI_Parser()

    try:
        with open(filename, 'r') as open_f:
            parser.read_file(open_f)
            return parser.get_ini_dict()
    except (OSError, PermissionError, UnicodeDecodeError,
            MissingSectionHeaderError, NoSectionError):
        pass

def csv_to_lol(file):
    """
    Returns:
        list of lists from the CSV file or None on failure
    """
    csv_data = []
    try:
        with open(file, 'r') as open_f:
            reader = csv.reader(open_f)
            return list(reader)
    except (OSError, PermissionError, UnicodeDecodeError):
        return None
                    
def verify_ds(ds_names):
    """
    """
    for _name in ds_names:
        if devtree.ds(name):
            return True
        else:
            return None

def search(term, devtree):
    """
    Search the device tree for a datasource
    
    Args:
        term (str):  name, IPv4/IPv6 address, hostname or datasource ID
                     for the datasource to locate
                     
        devtree (obj): devtree object to be searched

    Returns:
        dict (str:str) of datasource attributes
    """
    return devtree.search(term)
    
def main():
    """
    CLI processing
    """
    config = Config()
    pargs = get_args(sys.argv)
    esm = ESM()
    esm.login(host=config.esm_host, user=config.esm_user, 
                passwd=config.esm_passwd)
    
    if pargs.add:
        ds_dir = config.ds_dir
        dsdir_path = verify_dir(ds_dir)
        new_files = None
        new_files = scan_dir(dsdir_path)
        
        if not new_files:
            print("No datasource files found.")
            sys.exit(0)
        
        devtree = DevTree()
        ds_lod = convert_ds_files(new_files, types=config.types)
        
        recs = devtree.recs()

        """
        If a Receiver has multiple IPs due to HA mode or other reason,
        then the mfe_saw.ini needs to include a [recs] section as:
            
            rec_name=ip
            rec2_name=ip
        
        Where the rec_name is the name of the Receiver in the ESM and
        ip is the IP address where devices send logs and include in 
        the datasource configurion file as 'rec_ip'. This would be 
        different than the mgmt IP of the Receiver.
        
        This bit ties the IPs to the Receiver so we know which is which.
        """
        if config.recs:
            for rec_name, new_ip in config.recs.items():
                for rec in recs:
                    if rec_name.lower() == rec['name'].lower():
                        rec['rec_ip'] = [rec['ds_ip'], new_ip]
                    else:
                        rec['rec_ip'] = [rec['ds_ip']]
        
        """
        We must know the device ID of the Receiver to add a device
        to it but we only know the IP to send logs to. 
        
        This matches the IP in the datasource config to the Receiver 
        and sets the 'parent_id' field in the datasource dict.
        """
        for ds in ds_lod:
            for rec in recs:
                try:
                    if ds['rec_ip'] in rec['rec_ip']:
                        ds['parent_id'] = rec['ds_id']
                except KeyError:
                    pass
        client_grps = devtree._get_client_grps()
        
        dup_name = devtree.search(ds['name'], zone_id=ds.get('zone_id'))
        dup_ip = devtree.search(ds['ds_ip'], zone_id=ds.get('zone_id'))
        
        for ds in ds_lod:
            if dup_name:
                print('Duplicate datasource {}. Datasource not' 
                       'added: {} - {}.'.format(ds['name']. ds['ds_ip']))
                continue

            if dup_ip:
                print('Duplicate datasource IP. Datasource not' 
                       'added: {} - {}.'.format(ds['name']. ds['ds_ip']))
                continue

            client=None
            if ds.get('client'):
                client=True
                for grp in client_grps:
                    if grp['type_id'] == ds['type_id']:
                        ds['parent_id'] = grp['ds_id']
            ds = DataSource(**ds)
            ds_to_verify = []
            try:
                ds.add(client=client)
                ds_to_verify.append(ds.name)
            except ESMException:
                print('Duplicate datasource not added: {}.'.format(ds.name))
                continue

        
        devtree.refresh()
        for ds in ds_to_verify:
            if search(ds, devtree):
                print('DataSource successfully added: {}'.format(ds))
            else:
                print("Problem occured while adding datasource and it was not added.")
            
    if pargs.search:
        devtree = DevTree()
        print(search(pargs.search, devtree))

    
    if pargs.esm_version:
        print(esm.version())
        
        
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.warning("Control-C Pressed, stopping...")
        sys.exit()