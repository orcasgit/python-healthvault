from setuptools import setup

setup(
    name='python-healthvault',
    version='0.1.3',
    packages=['healthvaultlib'],
    url='https://github.com/orcasgit/python-healthvault',
    license='Apache 2.0',
    author='Dan Poirier and Caktus Group',
    author_email='dpoirier@caktusgroup.com',
    description='Python library to access Microsoft Healthvault',
    install_requires=['pycrypto>=2.6', 'sphinx'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ],
    setup_requires=['nose>=1.0'],
)
