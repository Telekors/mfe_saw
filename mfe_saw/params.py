# -*- coding: utf-8 -*-
"""
    mfe_saw.params
    ~~~~~~~~~~~~~

    This module imports a dict into the mfe_saw core class to provide
    a central place to aggregate methods and parameters. The params
    are stored as docstrings to support string replacement.

    Args:
        method (str): Dict key associated with desired function
        Use normal dict access, ['method'], or .pop('method')

    Returns:
        tuple: (string, string)

        The first string is the method name that is actually used as
        the URI or passed to the ESM. The second string is the params
        required for that method. Some params require variables be
        interpolated as documented in the Attributes.

    Example:
        method, params = params['login'].format(username, password)

    Attributes:
        login: Function to login
            vars:
                username
                password
            callback vars:
                Cookie
                X-Xsrf-Token

        devtree: Get top level device tree string

        client_grp: Get clients for a specific group
            vars:
                id
            callback vars:
                ftoken

        results: Get results from earlier call
            vars:
                ftoken

"""

PARAMS = {
    'login': ("login",
              """{'username': '%(_username)s',
                 'password' : '%(_password)s',
                 'locale': 'en_US',
                 'os': 'Win32'}
                 """),

    'get_devtree': ("GRP_GETVIRTUALGROUPIPSLISTDATA",
                    """{'ITEMS': '#{DC1 + DC2}',
                    'DID': '1',
                    'HD': 'F',
                    'NS': '0'}
                    """),

    'find_client_group': ("DS_GETDSCLIENTLIST",
                          """{'DSID': '%(group_id)s',
                            'SEARCH': ''}
                         """),

    'get_file': ("MISC_READFILE",
                 """{'FNAME': '%(ftoken)s',
                 'SPOS': '0',
                 'NBYTES': '0'}
                 """),

    'map_dtree': ("map_dtree",
                  """{'dev_type': '%(dev_type)s',
                  'name': '%(ds_name)s',
                  'ds_id': '%(ds_id)s',
                  'enabled': '%(enabled)s',
                  'ds_ip': '%(ds_ip)s',
                  'hostname' : '%(hostname)s',
                  'typeID': '%(type_id)s',
                  'vendor': '',
                  'model': '',
                  'tz_id': '',
                  'date_order': '',
                  'port': '',
                  'syslog_tls': '',
                  'client_groups': '%(client_groups)s'
                  }
                  """),
                 
    'add_parent': ("dsAddDataSource", 
                """ {'datasource': {
                        'parentId': {'id': '%(parent_id)s'},
                        'name': '%(name)s',
                        'id': {'id': '%(ds_id)s'},
                        'typeId': {'id': '%(type_id)s'},
                        'childEnabled': '%(child_enabled)s',
                        'childCount': '%(child_count)s',
                        'childType': '%(child_type)s',
                        'ipAddress': '%(ds_ip)s',
                        'zoneId': '%(zone_id)s',
                        'url': '%(url)s',
                        'enabled': '%(enabled)s',
                        'idmId': '%(idm_id)s'
                    }}"""),

    'add_client': ("DS_ADDDSCLIENT", 
                     """{'PID': '%(parent_id)s',
                     'NAME': '%(name)s',
                     'ENABLED': '%(enabled)s',
                     'IP': '%(ds_ip)s',
                     'HOST': '%(hostname)s',
                     'TYPE': '%(type_id)s',
                     'TZID': '%(tz_id)s',
                     'DORDER': '%(dorder)s',
                     'MASKFLAG': '%(maskflag)s',
                     'PORT': '%(port)s',
                     'USETLS': '%(syslog_tls)s'
                    }"""),
                    
    'get_recs': ("devGetDeviceList?filterByRights=false",
                     """{'types': ['RECEIVER']}
                     """),

    'get_dstypes': ("dsGetDataSourceTypes",
                     """{'receiverId': {'id': '%(rec_id)s'}
                        }
                     """),
                     
    'del_ds': ("dsDeleteDataSource",
                """{'receiverId': {'id': '%(parent_id)s'},
                    'datasourceId': {'id': '%(ds_id)s'}}
                 """),
                 
    'ds_last_times': ("QRY_GETDEVICELASTALERTTIME",
                      """
                      """),
                      
    'ds_by_type': ("QRY_GETDEVICECOUNTBYTYPE",
                      """
                      """),

   '_dev_types':  {'2', 'ERC',
                    '3', 'datasource',
                    '4', 'Database Event Monitor (DBM)',
                    '5', 'DBM Database',
                    '7', 'Policy Auditor',
                    '10', 'Application Data Monitor (ADM)',
                    '12', 'ELM'
                    '14', 'Local ESM',
                    '15', 'Advanced Correlation Engine (ACE)',
                    '17', 'Score-based Correlation',
                    '19', 'McAfee ePolicy Orchestrator (ePO)',
                    '20', 'EPO',
                    '21', 'McAfee Network Security Manager (NSP)',
                    '23', 'NSP Port',
                    '24', 'MVM',
                    '25', 'Enterprise Log Search (ELS)',
                    '254', 'client_group',
                    },
                    
    'ds_details': ("dsGetDataSourceDetail",
                    """{'datasourceId': 
                        {'id': '%(ds_id)s'}}
                    """)
}