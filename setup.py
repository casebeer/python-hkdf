#!/usr/bin/env python

from __future__ import print_function

from setuptools import setup
import sys

try:
	with open("README.rst", "rb") as f:
		readme = f.read().decode("utf-8")
except:
	readme = ""
	print("Warning, unable to load README.rst into long_description.")

setup(
	name="hkdf",
	version="0.0.1",
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
	]
)

