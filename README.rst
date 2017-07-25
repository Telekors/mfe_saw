McAfee SIEM API Wrapper: MFE_SAW
================================

.. image:: https://img.shields.io/pypi/v/mfe_saw.svg
        :target: https://pypi.python.org/pypi/mfe_saw

.. image:: https://img.shields.io/travis/andywalden/mfe_saw.svg
        :target: https://travis-ci.org/andywalden/mfe_saw

.. image:: https://readthedocs.org/projects/mfe_saw/badge/?version=latest
        :target: https://readthedocs.org/projects/mfe_saw/?badge=latest
        :alt: Documentation Status


MFE_SAW is a wrapper around the McAfee ESM API versions 10.x and above.

**It is time to SAW through repetitive SIEM tasks!**

.. image:: https://raw.githubusercontent.com/andywalden/mfe_saw/master/docs/_static/mfe_saw_bw.png
    :target: http://mfe-saw.readthedocs.io/en/latest/index.html
    
This project aims to provide a basic API wrapper around the McAfee SIEM API to help make it more accessible to as many people as possible. 




Whether it be to add the day's new datasources, querying the raw logs for 200 IP addresses for different date ranges or integrating a list of datasources that have been silent the past 24 hours into a report, when you're responsible for a repetitive task you should be spending your time automating, not repeating. It's time for MFE_SAW!

For SIEM operators, the project includes a CLI front end to automate tasks that would otherwise be time consuming or repetitive in the user interface.

For developers, this project attempts to provide a pythonic interface for specific aspects of the product including:
* ESM Monitoring
* Datasource Management (add, edit, del - including Client datasources)
* Simplified Query interface [TBD]
* Watchlist Operations [TBD]
 
The first target of this project is datasource management. With this library and accompanied front-end CLI interface, datasources can be easily added by providing a few details. 

dsconf/new_ds_cfg.txt

```
    name=DC01_DNS
    ip=10.10.1.34
    rec_ip=172.16.15.10
    type=linux
```
```
	$ mfe_saw -a 
	DataSource successfully added: DC01_DNS

```



.. code-block:: python

For the developers, here is another example:

.. code-block:: python

    >>> from mfe_saw.esm import ESM
	>>> from mfe_saw.datasource import DataSource, DevTree
	>>> esm = ESM()
	>>> esm.login('10.10.22.60', 'NGCP', 'password')
	>>> esm.time()
	'2017-07-25T13:32:57.0+0000'
	>>> tree = DevTree()
	>>> len(tree)
	1738
	>>> 'testbox-1' in tree
	True
	>>> tree.search('testbox-1')
    {"ds_id": "144119586172699648", "child_enabled": "false", "child_count": "0", "child_type": "0", "zone_id": "0", "url": null, "enabled": "T", "idm_id": "0", "hostname": "", "tz_id": "", "dorder": null, "maskflag": null, "port": "", "syslog_tls": "F", "vendor": "InterSect Alliance", "model": "Snare for Windows", "client_groups": "0", "desc_id": "256", "name": "testbox-1", "ds_ip": "10.10.23.17", "type_id": "0", "date_order": "", "zone_name": "", "client": true, "parent_id": "144119586172698624", "idx": 1691, "desc": "client", "parameters": [{"desc_id": "256", "hostname": "", "vendor": "InterSect Alliance", "model": "Snare for Windows", "tz_id": "", "date_order": "", "port": "", "syslog_tls": "F", "client_groups": "0", "zone_name": "", "client": true, "idx": 1691, "desc": "client"}]}
	>>>
	>>> testbox1 = tree.search('testbox-1')
	>>> type(testbox1)
	<class 'mfe_saw.datasource.DataSource'>
	>>> testbox1.delete()
	>>> tree.refresh()
	>>> tree.search('testbox-1')
	>>> 'testbox-1' in tree
	False
	>>> len(tree)
	1737

Feature Support
---------------
- Pythonic implementation
- Authentication and session tracking across objects
- Built-in multiprocessing for high performance
- Pass through of native API methods 
- CLI interface
- Get info for existing datasources
- Add new datasources 
- ESM status methods
- More to come!

mfe_saw officially supports Python 3.3–3.7 on Windows and Linux.

Installation
------------
To install MFE_SAW, use pip:

.. code-block:: bash

    $ pip install mfe_saw
    
Documentation
-------------
Documentation is available at http://mfe-saw.readthedocs.io/en/latest/index.html

Disclaimer
------------
_Note: This is an **UNOFFICIAL** project and is **NOT** sponsored or supported by **McAfee, Inc**. If you accidentally delete all of your datasources, don't call support (or me). Product access will always be limited to 'safe' methods and with respect to McAfee's intellectual property.  This project is released under the [ISC license](https://en.wikipedia.org/wiki/ISC_license), which is a permissive free software license published by the Internet Systems Consortium (ISC) and without warranty._
