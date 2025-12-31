.PHONY: test fixtures fixtures-ecdsa fixtures-eddsa build clean help

help:
	@echo "Available targets:"
	@echo "  build          - Build the recovery tool (ECDSA CLI)"
	@echo "  test           - Run tests"
	@echo "  fixtures       - Generate all test fixtures (ECDSA + EdDSA)"
	@echo "  fixtures-ecdsa - Generate ECDSA test fixtures"
	@echo "  fixtures-eddsa - Generate EdDSA test fixtures"
	@echo "  clean          - Clean build artifacts"

# Generate test fixtures
fixtures: fixtures-ecdsa fixtures-eddsa

fixtures-ecdsa:
	@echo "Generating ECDSA fixtures..."
	@cd scripts && python3 generate_fixtures.py

fixtures-eddsa:
	@echo "Generating EdDSA fixtures..."
	@python3 scripts/flawed_eddsa_signer.py

# Build Go recovery tool
build:
	@echo "Building recovery tool..."
	@go build -o bin/recovery ./cmd/recovery

# Run tests
test:
	@echo "Running tests..."
	@go test ./...

# Clean generated files
clean:
	@echo "Cleaning..."
	@rm -rf fixtures/*.json fixtures/*.yaml fixtures/*.txt
	@rm -rf bin/
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

