from setuptools import find_packages
from setuptools import setup


__VERSION__ = '2.0.1'


def requirements():
    with open('requirements.txt') as reqs:
        install_req = [
            line
            for line in
            reqs.read().split('\n')
        ][:-1]  # skip the EOF newline
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
    scripts=['trusttrees.py'],
    include_package_data=True,
)
