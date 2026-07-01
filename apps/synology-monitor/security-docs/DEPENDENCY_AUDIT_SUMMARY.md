# Synology Monitor Dependency and Supply Chain Summary

## 9. Update and Supply Chain Security

## 9.1 Package Signing

Current state: `Not Implemented` (in this community package baseline)

- `community-package/README.md` explicitly describes this package as a baseline without signing.

## 9.2 Update Verification

Current state: `Partially Implemented`

- `verify-release.sh` validates package metadata consistency, release URL format, and SHA-256/size fields.
- If local SPK exists, script compares computed hash and file size with `repo/packages.json`.
- This is integrity verification by checksum, not cryptographic publisher identity verification.

## 9.3 Installed File Integrity Verification at Startup

Current state: `Not Implemented`

- No startup routine verifies checksums/signatures of installed scripts or binaries.

## 9.4 Third-Party Dependency Pinning and Audit

Current state: `Not Implemented`

- No `requirements.txt` or lockfile with pinned versions in addon path.
- Optional imports (`werkzeug`, `pyotp`, `qrcode`, `Pillow`, `cryptography`) are not version-pinned in repo.
- No dependency-vulnerability audit artifact is present in current source tree.

## Software Supply Chain Documentation

### Current Controls

- SPK metadata contains SHA-256 and size fields.
- Release checklist includes hygiene and release validation steps.
- Build and verify scripts exist for packaging consistency checks.

### Gaps

- No package signing or signed update metadata.
- No dependency lock + audit report.
- `install.sh` downloads executable script from remote URL without checksum/signature verification.

### Recommended Next Controls

1. Introduce signed releases (SPK signing and/or signed manifest).
2. Add dependency lock files and reproducible dependency installation path.
3. Add automated dependency vulnerability scanning in CI.
4. Add checksum/signature verification in installer script.
5. Add startup self-checks for critical helper scripts and Python entrypoint.

