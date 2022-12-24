#!/bin/sh

export PYTHONPATH=$PWD

set -xeuo pipefail

find keycase/ -name '*.py' | xargs python -m doctest
mypy keycase/
pytest keycase/
yapf -dr keycase/
pylint keycase/
