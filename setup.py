#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='isafw',
      version='0.1',
      description='ISA FW',
      author='Elena Reshetova',
      author_email='elena.reshetova@intel.com',
      url='http://github.com/otcshare/isafw',
      packages=find_packages(),
      package_dir={'isaplugins': 'isafw/isaplugins'},
      package_data={'isafw': ['isaplugins/configs/la/*']},
     )
