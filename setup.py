"""
py2app setup configuration for Hassle Free PGP
Creates a standalone Mac .app bundle that users can double-click
"""

from setuptools import setup

APP = ['app.py']
APP_NAME = 'Hassle Free PGP'
VERSION = '1.0.0'

DATA_FILES = []

OPTIONS = {
    'argv_emulation': False,  # Don't use argv emulation (not needed for GUI)
    'iconfile': None,  # Add your .icns icon file here if you have one
    'plist': {
        'CFBundleName': APP_NAME,
        'CFBundleDisplayName': APP_NAME,
        'CFBundleGetInfoString': 'Offline PGP Encryption Made Simple',
        'CFBundleIdentifier': 'com.palwoth.hasslefreepgp',
        'CFBundleVersion': VERSION,
        'CFBundleShortVersionString': VERSION,
        'NSHumanReadableCopyright': 'Copyright © 2025 Pierce Alworth. All rights reserved.',
        'LSMinimumSystemVersion': '10.13.0',  # macOS High Sierra or later
        'LSApplicationCategoryType': 'public.app-category.utilities',
        'NSHighResolutionCapable': True,  # Support Retina displays
    },
    'packages': [
        'tkinter',
        'pgpy',
        'cryptography',
        'cffi',
        'pyasn1',
        'AppKit',
        'Foundation',
        'objc',
    ],
    'includes': [
        'app',
        'gui.keyring_view',
        'storage.key_store',
        'crypto.keys',
        'crypto.encrypt_decrypt',
        'crypto.sign_verify',
        'colors',
    ],
    'excludes': [
        'numpy',
        'scipy',
        'matplotlib',
        'pandas',
        'PIL',
    ],
    'resources': [],
    'frameworks': [],
    'site_packages': True,
    'strip': True,  # Strip debug symbols to reduce size
    'optimize': 2,  # Maximum optimization
}

setup(
    name=APP_NAME,
    app=APP,
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
    install_requires=[
        'pgpy>=0.6.0',
    ],
)

