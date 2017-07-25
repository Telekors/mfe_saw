===================
DataSource Class
===================

The DataSource class provides the interface to add, delete, edit and
otherwise interact with a datasource.

A DataSource object is initialized with a few required fields:

 * name
 * IP or hostname
 * parent ID
 * type ID

It is possible to initialize the object manually:

.. code-block:: python

    ds = DataSource(name='loghost1', ip='10.0.0.4', type_id=65, parent_id='144119601809063936')
    
But the primary factory for DataSource objects is the DevTree Class. At
this level, there is still some exposed machinery in the type_id and parent_id arguments.

For this, there are helper methods included to look up any value that might be 
required in operations. Most of them have been implemented in the ESM Class. For example:

 * esm.type_id_to_venmod() 
 * esm.venmod_to_type_id()
 
 More information can be found in the ESM Class documentation.
 
 

