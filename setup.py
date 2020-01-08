from setuptools import find_packages
from setuptools import setup


__VERSION__ = '3.0.0'


def requirements():
    with open('requirements.txt') as reqs:
        install_req = reqs.read().splitlines()
    return install_req


setup(
    name='TrustTrees',
    url='https://github.com/mandatoryprogrammer/TrustTrees',
    description='A Tool for DNS Delegation Trust Graphing',
    version=__VERSION__,
    long_description=(
        'Check out TrustTrees on `GitHub <https://github.com/mandatoryprogrammer/TrustTrees>`_!'
    ),
    keywords='subdomain, subdomain-takeover, dns, dnssec, security, bug-bounty, bugbounty',
    author='mandatoryprogrammer',
    packages=find_packages(),
    install_requires=requirements(),
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'trusttrees = trusttrees.__main__:main',
        ],
    },
)
