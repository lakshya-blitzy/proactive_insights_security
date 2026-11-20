# Security scanner fixtures

These files are intentionally small static-analysis fixtures.

- `insecure_yaml.py`: unsafe YAML loading pattern.
- `weak_crypto.py`: weak hashing and non-cryptographic randomness.
- `unsafe_tempfile.py`: predictable shared temporary-file path.
- `../requirements-vulnerable.txt`: deliberately old dependency versions for SCA testing.

Use these only in an isolated test repository. Do not install the outdated dependencies or deploy this code.
A scanner may report findings differently depending on enabled rules and vulnerability databases.
