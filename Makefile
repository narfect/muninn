.PHONY: run test compile seed clean help test-supabase-live

help:
	@echo "Muninn — make targets:"
	@echo "  make run      start the server (http://127.0.0.1:8000)"
	@echo "  make test     run the stdlib unittest suite"
	@echo "  make compile  syntax/import gate (compileall)"
	@echo "  make clean    remove the local db + memory + caches"
	@echo "  make test-supabase-live   run the live Supabase smoke test (needs env + MUNINN_SUPABASE_SMOKE=1)"

run:
	python3 -m backend.server

test:
	python3 -m unittest discover -s tests -t . -q

compile:
	python3 -m compileall backend tests

# Opt-in live smoke test against a real Supabase project. Requires SUPABASE_URL,
# SUPABASE_ANON_KEY (and SUPABASE_SERVICE_ROLE_KEY for cleanup) plus MUNINN_SUPABASE_SMOKE=1.
test-supabase-live:
	MUNINN_SUPABASE_SMOKE=1 python3 -m unittest tests.test_supabase_live_smoke -v

clean:
	rm -f data/muninn.db data/muninn.db-* data/memory_local.json
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
