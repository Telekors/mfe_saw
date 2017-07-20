# -*- coding: utf-8 -*-
"""
    mfe_saw __main__
    ~~~~~~~~~~~~~


"""
import json
import requests
import sys
try:
    from mfe_saw.esm import ESM
    from mfe_saw.datasource import DataSource
    from mfe_saw.utils import timethis
except ImportError:
    from esm import ESM
    from datasource import DataSource, DevTree
    from utils import timethis

@timethis
def main():
    """
    Main function
    """
    
main()


