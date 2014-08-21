# -*- coding: utf-8 -*-
import sys
from cx_Freeze import setup, Executable

base = None
if sys.platform == "win32":
    base = "Win32GUI"

executables = [
    Executable('blockcheck.py', base=base)
]

setup(name='blockcheck',
      version='0.0.5',
      description='BlockCheck',
      executables=executables,
      options = {'build_exe': {'init_script':'Console', 'compressed':'1', 'packages':'dns'}},
      )
