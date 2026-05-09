# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2026-05-08

### Fixed
- iOS: Re-added `s.dependency 'SynheartAuth'` to `synheart_auth.podspec`.
  The 0.1.2 podspec dropped the dep on the assumption that consumers
  would pull the native SDK via SwiftPM, but pub.dev consumers using
  CocoaPods (the default Flutter iOS toolchain) had no header/framework
  search path for the `SynheartAuth` module, so `import SynheartAuth` in
  `SynheartAuthPlugin.swift` failed with `Unable to resolve module
  dependency: 'SynheartAuth'`. The dep is now declared explicitly so
  CocoaPods wires up the search paths.

## [0.1.2] - 2026-05-08

### Changed
- Android: bumped Maven dep to `ai.synheart:synheart-auth:0.1.1`. Picks
  up `DeviceRegistrar` register/rotate race fix, `ClockSkewTracker`
  auto-applying skew on every signed request, `AuthNetworkClient`
  HTTP timeouts, and §13 audit-log PII redaction.

## [0.1.1] - 2026-05-08

### Fixed
- Android: Replaced filesystem-relative source include of
  `synheart-auth-kotlin` with the published Maven Central artifact
  (`ai.synheart:synheart-auth:0.1.0`). 0.1.0 only resolved when the
  Flutter plugin and the Kotlin SDK were sibling directories on disk —
  pub.dev consumers (where the package lives in `~/.pub-cache/`) saw
  `import ai.synheart.auth.registration.AttestationProvider` fail to
  resolve. 0.1.0 has been retracted on pub.dev for this reason.

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
