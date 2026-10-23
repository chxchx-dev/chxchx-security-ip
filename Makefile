.PHONY: venv install test check package integration namespace-integration doctor clean

venv:
	python3 -m venv .venv

install:
	.venv/bin/pip install -e . pytest build

test:
	.venv/bin/pytest

check: test
	bash -n install-fedora.sh install-remote-fedora.sh install-debian.sh install-remote-debian.sh

package:
	.venv/bin/python -m build --sdist --wheel

integration:
	CHXSEC_RUN_LIVE_TESTS=1 .venv/bin/pytest tests/integration

namespace-integration:
	CHXSEC_RUN_NAMESPACE_TESTS=1 .venv/bin/pytest tests/integration/test_live_namespace.py

doctor:
	.venv/bin/chxsec doctor

clean:
	rm -rf build dist .pytest_cache .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
