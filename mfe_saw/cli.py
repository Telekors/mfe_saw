# -*- coding: utf-8 -*-

"""Console script for mfe_saw"""

import argparse

try:
    from mfe_saw.esm import ESM
    from mfe_saw.datasource import Datasource, DevTree
except ModuleNotFoundError:
    from esm import ESM
    from datasource import Datasource, DevTree

    
class Args(object):

    def __init__(self, args):
        self.log_levels = ['quiet', 'error', 'warning', 'info', 'debug']
        self.output_formats = ['json', 'csv', 'raw', 'word']
        self.formatter_class = argparse.RawDescriptionHelpFormatter
        self.parser = argparse.ArgumentParser(
                formatter_class=self.formatter_class,
                description='McAfee SIEM API Wrapper'
            )
        self.args = args

        self.parser.add_argument('-a', '--add', 
                                 action='store_true', dest='add', default=None,
                                 help='Scan <dsdir> for new datasource files')

        self.parser.add_argument('-s', '--search', 
                                 dest='search', nargs='?', default=None, metavar='term',
                                 help='Search for datasource name, hostname, or IP.')
        
        self.parser.add_argument('-d', '--dsconf'
                                 action='store_true', dest='dssum', default=None,
                                 help='Print datasource configs.')

        self.parser.add_argument('-o', 
                                 choices=self.output_formats, dest='output',
                                         default='default', metavar='[format]',
                                 help=('Set output format of results. Default:'
                                        'columns with borders. '
                                        'Options: json, csv, raw, and word')
                                       
        self.parser.add_argument('-w', 
                                 action='store_true', dest='write',default=None,
                                 help='Write output to file.')
                                 
        self.parser.add_argument('-v', '--version', 
                                 action='version',
                                 help='Show version',
                                 version='%(prog)s {}'.format(__version__))

        self.parser.add_argument('-l', '--level',
                                 default=None, dest='level',
                                 choices=self.log_levels, metavar='',
                                 help='Logging output level. Default: warning')
        
        self.parser.add_argument('-c', '--config',
                                 default=None, dest='cfgfile', metavar='',
                                 help='Path to config file. Default: config.ini')                                 

        self.pargs = self.parser.parse_args()
            
    def get_args(self):
        return self.pargs

if __name__ == '__main__':
    main()
