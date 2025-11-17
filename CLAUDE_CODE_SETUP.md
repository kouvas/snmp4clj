# Claude Code Setup for snmp4clj

This document describes the setup and development workflow for the snmp4clj project.

## Prerequisites

- **Java**: OpenJDK 11 or higher (tested with OpenJDK 21)
- **Clojure**: Clojure 1.11+ (basic installation sufficient for running tests)

## Installation

### Ubuntu/Debian

```bash
# Install Java (if not already installed)
apt-get install -y openjdk-21-jdk

# Install Clojure (basic version from apt)
apt-get install -y clojure
```

### Verify Installation

```bash
java -version
clojure -e '(println "Clojure" (clojure-version))'
```

### Note on Clojure CLI Tools

The apt package provides a basic Clojure 1.11 installation. For full modern Clojure CLI functionality (exec aliases, tools.deps features), you can optionally install the official Clojure CLI from https://clojure.org/guides/install_clojure.

The project includes a `run-tests.sh` script that works with the basic apt installation.

## Project Structure

```
snmp4clj/
├── src/              # Source code
├── test/             # Test files
├── doc/              # Documentation
├── deps.edn          # Dependencies and build configuration
├── Makefile          # Development tasks
└── README.md         # Project overview
```

## Development Workflow

### Download Dependencies

```bash
make deps
```

### Running Tests

```bash
# Run unit tests (default)
make test

# Run unit tests explicitly
make test-unit

# You can also run tests directly
./run-tests.sh
```

**Note**: Integration tests require Docker and the modern Clojure CLI tools. The basic setup runs unit tests only.

### REPL

Start a Clojure REPL with the project loaded:

```bash
make repl
```

### Clean

Remove temporary build files:

```bash
make clean
```

## Test Configuration

The project uses standard `clojure.test` for unit tests.

### Test Structure

- **Unit tests**: Located in `test/kouvas/` directory
- **Integration tests**: Require Docker containers (not configured in basic setup)

### Dependencies

Tests use:
- `org.clojure/test.check` for property-based testing (auto-downloaded)
- Standard `clojure.test` framework
- `clj-test-containers` for integration tests (requires modern CLI)

## Common Tasks

| Command | Description |
|---------|-------------|
| `make help` | Show available make targets |
| `make deps` | Download all dependencies |
| `make test` | Run unit tests |
| `make test-all` | Run all tests |
| `make repl` | Start a REPL |
| `make clean` | Clean temporary files |

## Direct Commands

```bash
# Run unit tests directly
./run-tests.sh

# Start a basic REPL
clojure

# Or use the REPL with project code
clojure -cp src
```

### With Modern Clojure CLI (Optional)

If you install the modern Clojure CLI tools from https://clojure.org/guides/install_clojure:

```bash
# Run unit tests
clojure -X:test

# Run integration tests
clojure -X:integration-test

# Start REPL with reflection warnings
clojure -M:repl
```

## Notes

- This is a zero-dependency SNMP v2c client implementation
- The project uses standard Clojure data types with no mutability
- See [doc/BER.md](./doc/BER.md) for documentation on ASN.1 Basic Encoding Rules
