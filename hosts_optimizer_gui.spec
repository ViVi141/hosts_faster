# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['hosts_optimizer_gui.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('favicon.ico', '.'),
        ('version_info.txt', '.'),
    ],
    hiddenimports=[
        'dns.resolver',
        'dns.rdataclass',
        'dns.rdatatype',
        'aiohttp',
        'tkinter',
        'tkinter.ttk',
        'tkinter.messagebox',
        'tkinter.scrolledtext',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ArmaReforgerHostsOptimizer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # GUI应用，不显示控制台
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='favicon.ico',
    version_file='version_info.txt',
)

