# file: client/setup.py

from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='client',
    version='0.1.0',
    author='Hardik',
    description='A backend client for decentralized file storage.',
    package_dir={'': 'src'},
    packages=find_packages(where='src'),
    install_requires=requirements, 
    include_package_data=True,
    python_requires='>=3.8',
)