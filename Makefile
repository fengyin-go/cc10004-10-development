.PHONY: install backend frontend test

install:
	cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
	cd frontend && npm install

backend:
	cd backend && ./run.sh

frontend:
	cd frontend && npm run dev

test:
	cd backend && .venv/bin/python -W ignore -m tests.test_security_boundary
	cd backend && .venv/bin/python -W ignore -m tests.test_legacy_source_masking
	cd frontend && npm run build
