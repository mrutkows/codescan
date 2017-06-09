"""Setup for PyPi distribution."""
from distutils.core import setup
setup(
    name='codescan',
    packages=['codescan'],
    version='0.2.0',
    description='Simple configurable code scanner in Python.',
    author='Matt Rutkowski',
    author_email='mrutkowski91@gmail.com',
    url='https://github.com/mrutkows/codescan',
    # data_files=[
    #     ('bitmaps', ['bm/b1.gif', 'bm/b2.gif']),
    #     ('config', ['cfg/data.cfg']),
    #     ('/etc/init.d', ['init-script'])]
    # download_url='https://github.com/mrutkows/scancode/archive/0.1.tar.gz',
    keywords=['scanning', 'code', 'scan'],
    classifiers=(
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License'
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Topic :: Software Development'
        'Topic :: Software Development :: Build Tools'
    )
)
