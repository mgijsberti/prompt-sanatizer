# Check stage - Verifies the code for errors without building
check:
    cargo check

# Build stage - Compiles the code in debug mode
build:
    cargo build

# Test stage - Runs the test suite
test:
    cargo test

# Run stage - Executes the application
run:
    cargo run -- --input inputs/example.txt --output outputs/sanitized.txt --force

# Release stage - Compiles the code in release mode for optimized performance
release:
    cargo build --release
