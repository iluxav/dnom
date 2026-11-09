# dnom PoC: common commands. Run `make` to list them.
#
# Variables you can override: make run ONLY=fake-exfil, make replay BACKEND=local
BIN          := target/release/dnom
BACKEND      ?= jev
# Empty: every assessed episode goes to Jev (secrets in command lines are redacted).
# Set it to limit Jev to episodes whose command contains this text.
ONLY         ?=
INPUT        ?= lab/replay/fake-exfil.jsonl
MODEL        ?= qwen3.6:27b-q8_0
RUNS         ?= 5
STATE        := $(HOME)/.local/state/dnom
REPLAY_STATE := /tmp/dnom-replay
RECORDINGS   := lab/recordings

# The Jev key lives in .env (git-ignored). dnom also reads .env on its own.
-include .env
export TYPESAFE_API_KEY

# classify refuses to send everything to Jev unless told so explicitly.
CLASSIFY_FLAGS := --backend $(BACKEND) --model $(MODEL)
ifneq ($(strip $(ONLY)),)
  CLASSIFY_FLAGS += --only $(ONLY)
else ifeq ($(BACKEND),jev)
  CLASSIFY_FLAGS += --allow-all-to-jev
endif
# replay and bench run the synthetic fixtures; default them to the fake-exfil episode.
FIXTURE_ONLY := $(or $(strip $(ONLY)),fake-exfil)

.DEFAULT_GOAL := help
.PHONY: help build test fmt run collect execs net writes record fake-exfil \
        replay replay-dry bench log jev-check reset-baseline clean

help: ## List commands
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(firstword $(MAKEFILE_LIST)) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

# --- build -----------------------------------------------------------------------------

build: ## Build release binary (eBPF + userspace)
	cargo build --release

test: ## Run unit tests
	cargo test

fmt: ## Format code (needs nightly for rustfmt.toml options)
	cargo +nightly fmt

# --- live (needs sudo for the eBPF collector) ------------------------------------------

run: build ## Live: collect | classify (BACKEND=local|jev|none, ONLY=...)
	sudo $(BIN) collect | $(BIN) classify $(CLASSIFY_FLAGS)

collect: build ## Live: raw JSON events
	sudo $(BIN) collect

execs: build ## Live: each distinct command once
	sudo $(BIN) collect | jq -r --unbuffered 'select(.kind=="exec") | "\(.comm)  \(.argv | join(" "))"' | awk '!seen[$$0]++'

net: build ## Live: network connections
	sudo $(BIN) collect | jq -r --unbuffered 'select(.kind=="net") | "\(.comm)[\(.pid)]  \(.op) \(.dest)"'

writes: build ## Live: files opened for writing
	sudo $(BIN) collect | jq -r --unbuffered 'select(.kind=="open" and .write) | "\(.comm)[\(.pid)]  \(.path)"'

record: build ## Live: save raw events to lab/recordings/<time>.jsonl (Ctrl-C to stop)
	@mkdir -p $(RECORDINGS)
	@f=$(RECORDINGS)/$$(date +%Y%m%d-%H%M%S).jsonl; echo "recording to $$f"; sudo $(BIN) collect > $$f

fake-exfil: ## Run the harmless credential-theft simulation (in a 2nd terminal)
	./scripts/fake-exfil.sh

# --- offline (no sudo) -----------------------------------------------------------------

replay: build ## Classify a recording (INPUT=..., BACKEND=..., ONLY=...)
	@rm -rf $(REPLAY_STATE)
	$(BIN) classify --backend $(BACKEND) --model $(MODEL) --only $(FIXTURE_ONLY) --input $(INPUT) --learn 0 --state-dir $(REPLAY_STATE)

replay-dry: build ## Show which episodes a recording produces, no model
	@rm -rf $(REPLAY_STATE)
	$(BIN) classify --backend none --input $(INPUT) --learn 0 --state-dir $(REPLAY_STATE)

bench: build ## Time RUNS assessments of the fake-exfil episode (BACKEND=local|jev)
	@rm -rf $(REPLAY_STATE) && mkdir -p $(REPLAY_STATE)
	@for i in $$(seq $(RUNS)); do \
	  $(BIN) classify --backend $(BACKEND) --model $(MODEL) --only $(FIXTURE_ONLY) --input $(INPUT) --learn 0 \
	    --state-dir $(REPLAY_STATE) >/dev/null 2>$(REPLAY_STATE)/stderr.log \
	    || { cat $(REPLAY_STATE)/stderr.log; exit 1; }; \
	  rm -f $(REPLAY_STATE)/baseline.json; \
	done
	@jq -s '{backend: .[0].backend, model: .[0].model, runs: length, avg_ms: (map(.latency_ms) | add / length | floor), min_ms: (map(.latency_ms) | min), max_ms: (map(.latency_ms) | max)}' $(REPLAY_STATE)/assessments.jsonl

log: ## Show the last 10 live assessments
	@tail -n 10 $(STATE)/assessments.jsonl | jq -c '{ts, episode_id, backend, latency_ms, cmd: .episode.root.argv, answers: (.answers | map_values(.noul // .choice))}'

jev-check: ## Check the Jev key works (lists models, sends no episode data)
	@test -n "$$TYPESAFE_API_KEY" || { echo "TYPESAFE_API_KEY is empty: put it in .env"; exit 1; }
	@curl -sS -w '\nHTTP %{http_code}, %{time_total}s\n' -H "Authorization: Bearer $$TYPESAFE_API_KEY" https://api.typesafe.ai/v1/models

reset-baseline: ## Forget learned programs/destinations (next run learns again)
	rm -f $(STATE)/baseline.json

clean: ## Remove build output
	cargo clean
