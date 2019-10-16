from setuptools import setup, find_packages
from happyjwt import __version__


setup(
    name="happyjwt",
    version=__version__,
    keywords=("JWT", "jwt", "Json Web Token"),
    description="Simple JWT tool",
    license="MIT Licence",

    url="https://github.com/Mivinci/happyJWT",
    author="Leonard Mivinci",
    author_email="i@xjj.pub",

    packages=find_packages(),
    include_package_data=True,
    platforms="all",
    install_requires=[]
)
