.PHONY: install validate test coverage detonate all clean

install:
	pip install -r tools/requirements.txt

validate:
	python tools/validate_rules.py

test:
	pytest tests/unit -q

coverage:
	python tools/coverage_report.py

# Local detonation. Requires flightsim and threatest on PATH and an approved
# detonation host. Read docs/testing-strategy.md before running this anywhere
# that is not a lab.
detonate:
	threatest lint scenarios/network.threatest.yaml
	threatest run scenarios/network.threatest.yaml --output build/test-results.json

all: validate test coverage

clean:
	rm -rf build .pytest_cache
