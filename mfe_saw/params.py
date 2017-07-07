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
              """{'username': '%(username)s',
                 'password' : '%(password)s',
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

}

