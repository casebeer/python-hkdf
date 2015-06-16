#!/usr/bin/env python

from __future__ import print_function

from setuptools import setup
import sys

import os
# Don't use hardlinks while testing from vagrant guest fs
# http://stackoverflow.com/questions/7719380/python-setup-py-sdist-error-operation-not-permitted
if os.environ.get('USER','') == 'vagrant':
    del os.link

try:
	with open("README.rst", "rb") as f:
		readme = f.read().decode("utf-8")
except:
	readme = ""
	print("Warning, unable to load README.rst into long_description.")

setup(
	name="hkdf",
	version="0.0.3",
	description="HMAC-based Extract-and-Expand Key Derivation Function (HKDF)",
	author="Christopher H. Casebeer",
	author_email="",
	url="https://github.com/casebeer/python-hkdf",

	py_modules=["hkdf"],

	tests_require=["nose"],
	test_suite="nose.collector",

	long_description=readme,
	classifiers=[
		"License :: OSI Approved :: BSD License",
		"Intended Audience :: Developers",
		"Programming Language :: Python :: 2.6",
		"Programming Language :: Python :: 2.7",
		"Programming Language :: Python :: 3.3",
		"Programming Language :: Python :: 3.4",
	]
)

