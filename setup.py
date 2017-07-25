# -*- coding: utf-8 -*-

import os

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


with open('README.rst') as readme_file:
    readme = readme_file.read()

test_requirements = ['pytest', 'tox']
requirements = ['requests', 'prettytable']
    
    
setup(
    name='mfe_saw',
    version='0.0.4',
    description="McAfee SIEM API Wrapper (MFE_SAW) for McAfee ESM 10.x+",
    author="Andy Walden",
    author_email='aw@krakencodes.com',
    url='https://github.com/andywalden/mfe_saw',
    packages=['mfe_saw'],
    package_dir={'mfe_saw': 'mfe_saw'},
    entry_points = {'console_scripts': ['mfe_saw=mfe_saw.cli:main']},
    include_package_data=True,
    install_requires=requirements,
    license="ISC",
    keywords='mfe_saw',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3 :: Only'],
    test_suite='tests',
    tests_require=test_requirements,
    python_requires='>=3')
