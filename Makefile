.PHONY: help test test-unit test-integration repl clean deps

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

deps: ## Download dependencies
	@echo "Dependencies will be downloaded on first test run"

test: test-unit ## Run unit tests (default)

test-unit: ## Run unit tests only (skip integration tests)
	@chmod +x run-tests.sh
	@./run-tests.sh

test-integration: ## Run integration tests only
	@echo "Integration tests require modern Clojure CLI tools"
	@echo "Install from: https://clojure.org/guides/install_clojure"

test-all: test-unit ## Run all tests (unit + integration)
	@echo "Note: Only unit tests are currently configured"

repl: ## Start a REPL
	clojure -M:repl

clean: ## Clean temporary files
	rm -rf .cpcache target

# Default target
.DEFAULT_GOAL := help
