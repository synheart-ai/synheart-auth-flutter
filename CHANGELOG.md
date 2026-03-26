# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-04

### Added

- **SynheartAuth** facade — thin Dart wrapper over native platform SDKs via MethodChannel
- **Platform bridge** — `ai.synheart.auth` channel for iOS (Secure Enclave) and Android (Keystore)
- **Device registration** — `registerDevice()`, `isRegistered()`, `getDeviceId()`
- **Request signing** — `signRequest()` returns all 6 RFC-required auth headers
- **Key rotation** — `rotateKey()` with old-key-signs-new proof
- **Clock skew correction** — `correctClockSkew()` for server timestamp alignment
- **Error types** — 11 sealed error subtypes matching RFC-AUTH-MOBILE-0001
- **State machine** — `DeviceAuthState` enum with validated transitions
- **Test support** — `SynheartAuth.forTesting(bridge:)` constructor for mock injection
- **Native plugins** — `SynheartAuthPlugin` for both iOS (Swift) and Android (Kotlin)
- **Unit tests** — 5 test files covering facade, bridge, models, errors, and state transitions
