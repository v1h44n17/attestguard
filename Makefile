CONTRACT := contracts/attest-guard-envelope

.PHONY: setup build test lint bench deploy start demo

setup: ## Install verifier dependencies
	cd verifier && npm ci

build: ## Compile the contract to wasm
	cd $(CONTRACT) && cargo near build non-reproducible-wasm

test: ## Run every test: contract unit + sandbox, verifier
	cd $(CONTRACT) && cargo test
	cd verifier && npm test

lint: ## Formatting, clippy with warnings denied, wasm check, typecheck
	cd $(CONTRACT) && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo check --target wasm32-unknown-unknown
	cd verifier && npm run typecheck

bench: ## Latency of the off-chain gate
	cd verifier && npm run bench

deploy: build ## Deploy to testnet: make deploy MASTER=you.testnet
	cd verifier && npm run deploy -- $(MASTER)

start: ## Serve the console at http://localhost:8787
	cd verifier && npm start

demo: ## Run both scenarios in the terminal
	cd verifier && npm run demo
