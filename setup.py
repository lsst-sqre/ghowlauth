#!/usr/bin/env python
"""Setup Tools Script"""
import os
import codecs
from setuptools import setup, find_packages

PACKAGENAME = 'sqre-ghowlauth'
DESCRIPTION = 'JupyterHub authenticator that uses GH orgs as whitelists'
AUTHOR = 'Adam Thornton'
AUTHOR_EMAIL = 'frossie@lsst.org'
URL = 'https://github.com/lsst-sqre/ghowlauth'
VERSION = '0.0.7'
LICENSE = 'MIT'


def read(filename):
    """Convenience function for includes"""
    full_filename = os.path.join(
        os.path.abspath(os.path.dirname(__file__)),
        filename)
    return codecs.open(full_filename, 'r', 'utf-8').read()


LONG_DESCRIPTION = read('README.md')


setup(
    name=PACKAGENAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    url=URL,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    license=LICENSE,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'License :: OSI Approved :: MIT License',
    ],
    keywords='lsst',
    packages=find_packages(exclude=['docs', 'tests*']),
    install_requires=[
        'oauthenticator>=0.5.1',
        'tornado>=4.1'
    ]
)
