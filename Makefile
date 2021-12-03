VIRTUALENV = $(shell which virtualenv)
PYTHONEXEC = python

VERSION = `grep VERSION version.py | cut -d \' -f2`

bandit: pydeps
	. venv/bin/activate; bandit -r pam/

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
	. venv/bin/activate; python setup.py install

inspectortiger: pydeps
	. venv/bin/activate; inspectortiger pam/

lint: pydeps
	. venv/bin/activate; python -m flake8 pam/ --max-line-length=120

preflight: bandit coverage test

pydeps:
	. venv/bin/activate; pip install --upgrade -q pip; \
	  pip install --upgrade -q pip flake8 bandit \
	  pyre-check coverage pytest pytest-mock pytest-cov pytest-runner \
	  mock minimock faker responses

test: pydeps deps venv lint
	. venv/bin/activate; \
	pytest tests -r w --capture=sys -vvv --cov; \
	coverage html

tox:
	. venv/bin/activate; tox

venv:
	$(VIRTUALENV) -p $(PYTHONEXEC) venv
