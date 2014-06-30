# -*- coding: utf-8 -*-
from cx_Freeze import setup, Executable

executables = [
    Executable('blockcheck.py')
]

setup(name='blockcheck',
      version='0.1',
      description='BlockCheck',
      executables=executables,
      options = {'build_exe': {'init_script':'Console', 'compressed':'1'}},
      )