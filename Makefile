.PHONY: test fixtures build clean

# Generate test fixtures
fixtures:
	@echo "Generating fixtures..."
	@cd scripts && python3 generate_fixtures.py

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

