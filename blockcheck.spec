# -*- mode: python -*-

from PyInstaller.utils.hooks import exec_statement
sys_os = exec_statement("""
    import sys
    print(sys.platform)""").strip()
ca_bundle = []
if sys_os == 'linux':
    ca_bundle = [('/etc/ssl/certs/ca-certificates.crt', 'lib')]

block_cipher = None


a = Analysis(['blockcheck.py'],
             pathex=[],
             binaries=[],
             datas=ca_bundle,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)

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
