from setuptools import setup

required = [line for line in open('requirements/base.txt').read().split("\n")]
required_dev = [line for line in open('requirements/test.txt').read().split("\n")]

setup(
    name='python-healthvault',
    version='0.1.5',
    packages=['healthvaultlib'],
    url='https://github.com/orcasgit/python-healthvault',
    license='Apache 2.0',
    author='Dan Poirier and Caktus Group',
    author_email='dpoirier@caktusgroup.com',
    description='Python library to access Microsoft Healthvault',
    install_requires=required,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ],
    test_suite='nose.collector',
    tests_require=required_dev,
)
