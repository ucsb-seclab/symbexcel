import setuptools

setuptools.setup(
    name='symbexcel',
    packages=['symbexcel'],
    version='0.1.0',
    author='Nicola Ruaro, Fabio Pagani',
    author_email='ruaronicola@ucsb.edu',
    description='A symbolic deobfuscator for XL4 macros',
    url='https://github.com/ruaronicola/symbexcel',
    install_requires=['dill', 'ipython', 'lark<1', 'matplotlib', 'msoffcrypto-tool', 'networkx', 'pebble', 'pygraphviz',
                      'pyparsing<3', 'pytest', 'pyxlsb2', 'scipy', 'untangle', 'python-dotenv', 'oletools', 'defusedxml',
                      'xlrd2 @ git+https://github.com/ruaronicola/xlrd2.git',
                      'z3-solver==4.8.10.0'],
    python_requires='>=3.6',
)
