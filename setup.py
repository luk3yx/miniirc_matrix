#!/usr/bin/python3

import pathlib
from setuptools import setup

setup(
    name='miniirc_matrix',
    version='0.0.1',
    py_modules=['miniirc_matrix'],
    author='luk3yx',
    description='A Matrix wrapper for miniirc.',
    license='MIT',

    long_description=pathlib.Path('README.md').read_text(),
    long_description_content_type='text/markdown',
    install_requires=[
        'requests>=2.22.0,<3',
        'miniirc>=1.7.0,<2',
    ],
    python_requires='>=3.8',

    classifiers=[
        'Intended Audience :: Developers',
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries',
    ]
)
