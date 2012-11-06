from distutils.core import setup

setup(
    name='python-healthvault',
    version='0.0.1',
    packages=['healthvaultlib', 'healthvaultlib.Crypto', 'healthvaultlib.Crypto.PublicKey',
              'healthvaultlib.Crypto.Util', 'webapp'],
    url='https://github.com/caktus/python-healthvault',
    license='Apache 2.0',
    author='Dan Poirier and Caktus Group',
    author_email='dpoirier@caktusgroup.com',
    description='Python library to access Microsoft Healthvault'
)
