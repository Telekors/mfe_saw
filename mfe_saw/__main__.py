# -*- coding: utf-8 -*-
"""
    mfe_saw __main__
    ~~~~~~~~~~~~~


"""
import sys
try:
    from mfe_saw.esm import ESM
    from mfe_saw.datasource import Datasource
except ModuleNotFoundError:
    from esm import ESM
    from datasource import Datasource, DevTree



def main():
    """
    Main function
    """
