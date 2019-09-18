# -*- mode: python -*-

from PyInstaller.utils.hooks import exec_statement
sys_os = exec_statement("""
    import sys
    print(sys.platform)""").strip()

add_datas = []
hooks_p = []
hooks_r = []

if sys_os == 'linux':
    ca_bundle = [('/etc/ssl/certs/ca-certificates.crt', 'lib')]
    add_datas = ca_bundle

if sys_os == 'darwin':
    add_datas = [('/System/Library/Frameworks/Tk.framework/Tk', '.'),
                 ('/System/Library/Frameworks/Tcl.framework/Versions/8.5/Tcl', '.'),
                ]
    hooks_p = ['osx_hooks']
    hooks_r = ['osx_hooks/loader/pyi_rth__tkinter.py']

block_cipher = None


a = Analysis(['blockcheck.py'],
             pathex=[],
             binaries=[],
             datas=add_datas,
             hiddenimports=[],
             hookspath=hooks_p,
             runtime_hooks=hooks_r,
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
			 noarchive=False)

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

a.binaries -= [
                   ('libffi.so.6', None, None),
                   ('libfontconfig.so.1', None, None),
                   ('libfreetype.so.6', None, None),
                   ('libbz2.so.1.0', None, None),
                   ('libX11.so.6', None, None),
                   ('libXau.so.6', None, None),
                   ('libXdmcp.so.6', None, None),
                   ('libXext.so.6', None, None),
                   ('libXft.so.2', None, None),
                   ('libXrender.so.1', None, None),
                   ('libXss.so.1', None, None),
                   ('libz.so.1', None, None),
                   ('libreadline.so.6', None, None),
                   ]

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='blockcheck',
          debug=False,
          strip=False,
          upx=True,
          console=False )

exe_folder = EXE(pyz,
          a.scripts,
          [],
          name='blockcheck_folder',
          exclude_binaries=True,
          debug=False,
          strip=False,
          upx=True,
          console=False )

coll = COLLECT(exe_folder,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               upx_exclude=[],
               name='blockcheck')

if sys_os == 'darwin':
    app = BUNDLE(exe,
                 name='blockcheck.app',
                 icon=None,
                 bundle_identifier=None)
