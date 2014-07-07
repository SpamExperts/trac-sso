from setuptools import setup

PACKAGE = 'TracSSO'
VERSION = '0.1'

setup(name=PACKAGE,
      version=VERSION,
      packages=['sso'],
      entry_points={'trac.plugins': '%s = sso' % PACKAGE},
)
