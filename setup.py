import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='keycase',
    version='0.1.0-alpha1',
    author='Peter Sanders',
    description='TOTP Authenticator',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/hxtk/keycase',
    packages=setuptools.find_packages(),
    install_requires=[
        'cryptography',
        'absl-py',
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
