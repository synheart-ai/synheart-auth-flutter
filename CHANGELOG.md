# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.5] - 2026-05-24

### Fixed
- Android: route Play Integrity callbacks (`addOnSuccessListener` /
  `addOnFailureListener`) through a dedicated single-thread executor
  instead of the default Android main thread. Symptom this fixes:
  during the first consent grant on a fresh install, the host app's
  UI froze for several seconds while the FFI worker isolate sat on
  `latch.await()` waiting for the Play Integrity result — the callback
  was queued behind whatever else the main thread was doing (Flutter
  input dispatch, surface compositor work, the IntegrityService
  binding callback itself). With a dedicated executor (named
  `syn-integrity-callback`, daemon thread) the latch resolves the
  instant Play Services hands the result back, regardless of main-
  thread load. Doesn't reduce the cold Play Integrity bind latency
  itself (that's owned by Google Play Services) but it stops the
  resolution from being held behind unrelated main-thread work.

## [0.1.4] - 2026-05-24

### Documentation
- iOS: replaced the misleading "consumed via SwiftPM" podspec comment
  with the actual incantation host Podfiles need. SynheartAuth is
  distributed from git, not the CocoaPods trunk spec repo, so each
  consuming app must declare the source explicitly:

      pod 'SynheartAuth',
          :git => 'https://github.com/synheart-ai/synheart-auth-swift.git',
          :tag => 'v0.1.0'

  No code or behaviour change; the `s.dependency 'SynheartAuth'` line
  (restored in 0.1.3) remains. The previous comment implied SwiftPM
  was sufficient, which led at least one downstream consumer to drop
  the pod source and then hit `Unable to resolve module dependency:
  'SynheartAuth'` at compile time.

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
