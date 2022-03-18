VIRTUALENV = $(shell which virtualenv)
PYTHONEXEC = python

VERSION = `grep VERSION src/pam/version.py | cut -d \' -f2`

build: pydeps
	python -m build

clean:
	rm -rf *.egg-info/
	rm -rf .cache/
	rm -rf .tox/
	rm -rf .coverage
	rm -rf build
	rm -rf dist
	rm -rf htmlcov
	rm -rf venv
	find . -type d -name '__pycache__' | xargs rm -rf
	find . -name "*.pyc" -type f -print0 | xargs -0 /bin/rm -rf

compile:
	. venv/bin/activate; python setup.py build install

console:
	. venv/bin/activate; python

coverage:
	. venv/bin/activate; coverage html

current:
	@echo $(VERSION)

deps:
	. venv/bin/activate; python -m pip install --upgrade -qr requirements.txt

install: clean venv deps
	. venv/bin/activate; pip install --use-pep517 --progress-bar emoji

inspectortiger: pydeps
	. venv/bin/activate; inspectortiger src/pam/

lint: pydeps
	. venv/bin/activate; python -m flake8 src/pam/ --max-line-length=120

preflight: bandit test

publish-pypi-test: clean venv build
	. venv/bin/activate; \
	python3 -m pip install --upgrade twine && \
	python3 -m twine upload --repository testpypi dist/*

publish-pypi: clean venv build
	. venv/bin/activate; \
	python3 -m pip install --upgrade twine && \
	python3 -m twine upload --repository pypi dist/*

pydeps:
	. venv/bin/activate; \
	  pip install --upgrade -q pip && \
	  pip install --upgrade -q pip build

test: tox

tox:
	rm -fr .tox
	. venv/bin/activate; tox

venv:
	$(VIRTUALENV) -p $(PYTHONEXEC) venv
