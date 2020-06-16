# -*- coding: utf-8 -*-

from setuptools import setup

from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, '../README.md'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='ssh_mitm_victim_finder',
    author='Joe Testa',
    author_email='jtesta@positronsecurity.com',
    version='0.0.1',
    description='find possible ssh mitm victims',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url="https://github.com/jtesta/ssh-mitm",
    py_modules=['JoesAwesomeSSHMITMVictimFinder'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Topic :: System :: Networking"
    ],
    entry_points={
        'console_scripts': [
            'ssh-proxy-server = ssh_proxy_server.cli:main'
        ]
    },
    install_requires=[
        'netaddr',
        'netifaces'
    ]
)
