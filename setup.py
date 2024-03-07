"""
This file is part of Python Salsa20
a Python bridge to the libsodium C [X]Salsa20 library

Released under The BSD 3-Clause License
Copyright (c) 2013 Keybase

setup.py - build and package info
"""

from distutils.core import setup, Extension
from glob import glob
from setuptools import setup, find_namespace_packages
from ecc import __version__


dependencies = [
    "dataclasses",
]

salsa20_module = Extension(
    "_salsa20",
    sources=glob("libsodium-salsa20/*.c") + ["salsa20.c"],
    include_dirs=["libsodium-salsa20"],
)

