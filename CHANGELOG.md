# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-04

Initial release.

- Request signing for HSI ingest via the `ai.synheart.auth` MethodChannel
  (iOS Secure Enclave / Android Keystore on the native side).
- `signRequest()` returns the six wire headers (X-App-ID, X-Device-ID,
  X-Synheart-Signature, X-Synheart-Timestamp, X-Synheart-Nonce,
  X-Synheart-Sig-Version).
- `correctClockSkew(serverTimestamp)` to align the device clock with
  the server.
- Typed `DeviceAuthState` lifecycle and `SynheartAuthError` hierarchy.
- `SynheartAuth.forTesting(bridge:)` for mock injection.

Note: `registerDevice()` and `rotateKey()` are exposed on the API for
parity but currently throw `UnsupportedError`. Device registration and
key rotation are performed by the native runtime; this Flutter
shell only signs.
