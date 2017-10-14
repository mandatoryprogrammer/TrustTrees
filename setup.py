from setuptools import setup, find_packages
__VERSION__ = "1.0.0"

def requirements():
    with open('requirements.txt') as reqs:
        install_req = [line for line in reqs.read().split('\n')]
    return install_req

def readme():
    with open("README.md") as f:
        return f.read()

setup(
    name="TrustTree",
    url="https://github.com/mandatoryprogrammer/TrustTrees",
    description="A Tool for DNS Delegation Trust Graphing",
    version=__VERSION__,
    long_description=readme(),
    keywords="trusttree, dns, dnssec",
    author="mandatoryprogrammer",
    packages=find_packages(),
    install_requires=requirements(),
    scripts=['trusttrees.py'],
    include_package_data=True
)
