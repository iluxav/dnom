# dnom PoC: common commands. Run `make` to list them.
#
# Variables you can override: make run ONLY=fake-exfil, make falco QUIET=1, make replay BACKEND=local
# BACKEND is a name from `backends:` in dnom.yaml (or none); MODEL overrides its model.
BIN          := target/release/dnom
BACKEND      ?= jev
# Empty: every assessed episode goes to Jev (secrets in command lines are redacted).
# Set it to limit Jev to episodes whose command contains this text.
ONLY         ?=
INPUT        ?= lab/replay/fake-exfil.jsonl
MODEL        ?=
RUNS         ?= 5
STATE        := $(HOME)/.local/state/dnom
REPLAY_STATE := /tmp/dnom-replay
RECORDINGS   := lab/recordings
FALCO_IMAGE  ?= falcosecurity/falco:0.45.2
# Kev (self-hosted decision model) for --backend kev. Install once:
#   git clone https://github.com/jaredpalmer/kev $(KEV_DIR) && cd $(KEV_DIR) && uv sync --extra serve
KEV_DIR      ?= $(HOME)/.local/share/dnom-lab/kev
KEV_MODEL    ?= jaredpalmer/kev-0.8b
# KEV_GPU: a GPU index or UUID (nvidia-smi -L); empty = let Kev pick.
KEV_GPU      ?=
# Lab VM (lab/vm/vm.sh): Ubuntu 26.04 under QEMU/KVM, networked via passt (no host access).
VM           := lab/vm/vm.sh
NAME         ?= clean
# VM episodes get their own baseline and log, separate from the desktop's.
VM_STATE     := $(HOME)/.local/state/dnom/vm
VM_LEARN     ?= 30
# Official Falco container with only the dnom catch-all rules; nothing is installed on the host
# and /etc/falco is not touched. JSON alerts go to stdout; Falco's own log (warnings and
# errors only) goes to FALCO_LOG so it doesn't mix with dnom's output.
FALCO_LOG    := $(STATE)/falco.log
FALCO_RUN    := sudo docker run --rm --name dnom-falco --privileged \
  -v /proc:/host/proc:ro -v /etc:/host/etc:ro -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v $(CURDIR)/integrations/falco:/etc/falco/dnom:ro \
  --entrypoint /usr/bin/falco $(FALCO_IMAGE) \
  -r /etc/falco/dnom/dnom-catchall.yaml -o json_output=true -o engine.kind=modern_ebpf \
  -o log_level=warning -o log_syslog=false 2>>$(FALCO_LOG)

# The Jev key lives in .env (git-ignored). dnom also reads .env on its own.
-include .env
export TYPESAFE_API_KEY

# classify refuses to send everything to Jev unless told so explicitly.
MODEL_FLAG   := $(if $(strip $(MODEL)),--model $(MODEL))
# QUIET=1: print only episodes a policy rule matched (everything is still logged).
QUIET        ?=
CLASSIFY_FLAGS := --backend $(BACKEND) $(MODEL_FLAG) $(if $(strip $(QUIET)),--matches-only)
ifneq ($(strip $(ONLY)),)
  CLASSIFY_FLAGS += --only $(ONLY)
else
  # Only matters for backends on another machine (Jev); ignored for local ones.
  CLASSIFY_FLAGS += --allow-all-remote
endif
# replay and bench run the synthetic fixtures; default them to the fake-exfil episode.
FIXTURE_ONLY := $(or $(strip $(ONLY)),fake-exfil)

.DEFAULT_GOAL := help
.PHONY: help build test fmt run collect execs net writes record fake-exfil falco falco-events falco-stats falco-stop kev-serve \
        vm-setup vm-start vm-ssh vm-check vm-stop vm-snapshot vm-reset vm-status vm-destroy \
        vm-push vm-run vm-fake-exfil vm-e2e \
        replay replay-dry bench log jev-check reset-baseline clean

help: ## List commands
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(firstword $(MAKEFILE_LIST)) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

# --- build -----------------------------------------------------------------------------

build: ## Build release binary (eBPF + userspace)
	cargo build --release

test: ## Run unit tests
	cargo test

fmt: ## Format code (needs nightly for rustfmt.toml options)
	cargo +nightly fmt

# --- live (needs sudo for the eBPF collector) ------------------------------------------

run: build ## Live: collect | classify (BACKEND=<name in dnom.yaml>|none, ONLY=...)
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

falco: build ## Live: Falco (official container) + dnom catch-all rules -> classify
	@mkdir -p $(STATE); echo "Falco log: $(FALCO_LOG)  (tail -f it if nothing shows up)"
	$(FALCO_RUN) | $(BIN) classify --source falco $(CLASSIFY_FLAGS)

falco-stop: ## Stop a Falco container left running (only one falco* target can run at a time)
	sudo docker rm -f dnom-falco

falco-stats: ## Live: alerts per dnom rule every 5 s (quick health check)
	@mkdir -p $(STATE); echo "Falco log: $(FALCO_LOG)"
	$(FALCO_RUN) | jq -r --unbuffered '.rule' | awk '{c[$$1]++} systime()-t>=5 {t=systime(); s=""; for (k in c) s=s k"="c[k]"  "; print strftime("%T"), s; fflush(); delete c}'

falco-events: ## Live: every alert the dnom rules emit, one per line (debugging only, very noisy)
	@mkdir -p $(STATE); echo "Falco log: $(FALCO_LOG)"
	$(FALCO_RUN) | jq -rc --unbuffered '"\(.rule)  \(.output_fields | del(."evt.rawtime"))"'

# --- lab VM ------------------------------------------------------------------------------
# Needs: sudo pacman -S qemu-base libisoburn passt

vm-setup: ## Lab VM: download + verify Ubuntu 26.04, create disk and cloud-init seed (once)
	$(VM) setup

vm-start: ## Lab VM: boot and wait until ready (first boot provisions, ~3-8 min)
	$(VM) start

vm-ssh: ## Lab VM: shell as user lab
	$(VM) ssh

vm-check: ## Lab VM: verify provisioning, bpf LSM, tools, internet, and no host access
	$(VM) check

vm-push: build ## Lab VM: copy dnom and the test scripts into the VM (~/dnom)
	$(VM) push

vm-run: build ## Lab VM: dnom collect in the VM, classify here (the Jev key never enters the VM)
	@mkdir -p $(VM_STATE)
	$(VM) ssh 'sudo ~/dnom/dnom collect' | $(BIN) classify --remote-source --home /home/lab \
	  --state-dir $(VM_STATE) --learn $(VM_LEARN) $(CLASSIFY_FLAGS)

vm-fake-exfil: ## Lab VM: run the harmless credential-theft simulation inside the VM
	$(VM) ssh 'cd ~/dnom && ./scripts/fake-exfil.sh'

vm-e2e: ## Lab VM: end-to-end tests (unit tests, sensors, episodes, policies; Jev if keyed)
	lab/vm/e2e/run.sh

vm-stop: ## Lab VM: clean shutdown
	$(VM) stop

vm-snapshot: ## Lab VM: save a snapshot of the stopped VM (NAME=clean)
	$(VM) snapshot $(NAME)

vm-reset: ## Lab VM: revert the stopped VM to a snapshot (NAME=clean)
	$(VM) reset $(NAME)

vm-status: ## Lab VM: running or not, and its snapshots
	$(VM) status

vm-destroy: ## Lab VM: delete disk, seed and key (keeps the downloaded image)
	$(VM) destroy --yes

kev-serve: ## Start Kev on 127.0.0.1:8009 for --backend kev (KEV_MODEL=..., KEV_GPU=...)
	cd $(KEV_DIR) && $(if $(strip $(KEV_GPU)),CUDA_VISIBLE_DEVICES=$(KEV_GPU)) \
	  uv run --extra serve python -m kev.serve --run $(KEV_MODEL) --port 8009 --device cuda

fake-exfil: ## Run the harmless credential-theft simulation (in a 2nd terminal)
	./scripts/fake-exfil.sh

# --- offline (no sudo) -----------------------------------------------------------------

replay: build ## Classify a recording (INPUT=..., BACKEND=..., ONLY=...)
	@rm -rf $(REPLAY_STATE)
	$(BIN) classify --backend $(BACKEND) $(MODEL_FLAG) --only $(FIXTURE_ONLY) --input $(INPUT) --learn 0 --state-dir $(REPLAY_STATE)

replay-dry: build ## Show which episodes a recording produces, no model
	@rm -rf $(REPLAY_STATE)
	$(BIN) classify --backend none --input $(INPUT) --learn 0 --state-dir $(REPLAY_STATE)

bench: build ## Time RUNS assessments of the fake-exfil episode (BACKEND=local|jev)
	@rm -rf $(REPLAY_STATE) && mkdir -p $(REPLAY_STATE)
	@for i in $$(seq $(RUNS)); do \
	  $(BIN) classify --backend $(BACKEND) $(MODEL_FLAG) --only $(FIXTURE_ONLY) --input $(INPUT) --learn 0 \
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
