from setuptools import setup, find_packages            # 这个包没有的可以pip一下

setup(
    name="happyJWT",      # 这里是pip项目发布的名称
    version="0.1.1",       # 版本号，数值大的会优先被pip
    keywords=("JWT", "jwt", "Json Web Token"),
    description="JWT tool for your Python Web programming",
    long_description="Happiness comes from simpleness",
    license="MIT Licence",

    url="https://github.com/Mivinci/happyJWT/tree/master/hap-pyJWT",     # 项目相关文件地址，一般是github
    author="Leonard Mivinci",
    author_email="1366723936@qq.com",

    packages=find_packages(),
    include_package_data=True,
    platforms="all",
    install_requires=[]          # 这个项目需要的第三方库
)