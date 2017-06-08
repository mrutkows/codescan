"""Setup for PyPi distribution."""
from distutils.core import setup
setup(
    name='codescan',
    packages=['codescan'],
    version='0.8',
    description='Simple configurable code scanner in Python.',
    author='Matt Rutkowski',
    author_email='mrutkowski91@gmail.com',
    url='https://github.com/mrutkows/codescan',
    # download_url='https://github.com/mrutkows/scancode/archive/0.1.tar.gz',
    keywords=['scanning', 'code', 'scan'],
    # classifiers=[],
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
