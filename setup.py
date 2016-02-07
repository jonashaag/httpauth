from distutils.core import setup

setup(
    name='httpauth',
    version='0.3',
    author='Jonas Haag',
    author_email='jonas@lophus.org',
    url='https://github.com/jonashaag/httpauth',
    license='2-clause BSD',
    description="WSGI HTTP Digest Authentication middleware",
    py_modules=['httpauth'],
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ]
)
