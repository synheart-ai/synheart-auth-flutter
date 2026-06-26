# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.7] - 2026-06-26

### Fixed
- Android: `NativeCryptoBridge.getAttestation` now waits on the Play
  Integrity `CountDownLatch` with a 30-second timeout instead of
  blocking indefinitely. Play Integrity is supposed to invoke one of
  its success/failure listeners, but a stalled `IntegrityService` bind
  — no Play Store, an unlinked package, or a sideloaded debug build
  whose cloud project can't be resolved — can leave the `Task` pending
  forever. Before this fix the calling FFI isolate parked on
  `latch.await()` with no exit, so device registration never reached a
  terminal state and the host UI sat on "Setting up your workspace"
  with no error (and a SIGQUIT/ANR during the cold bind). A timeout is
  now treated as `{"format":"none","blob":""}` (attestation
  unavailable), letting the runtime fail fast and fall back / retry.
  This complements 0.1.5 (callbacks off the main thread) and 0.1.6
  (main-thread guard) — those addressed *slow* resolution; this
  addresses resolution that *never arrives*.
- Android: `PlayIntegrityAttestationProvider` (coroutine variant) wraps
  its token request in `withTimeoutOrNull` with the same 30-second cap,
  for parity with the JNI bridge path.

## [0.1.6] - 2026-05-26

### Added
- Android: `NativeCryptoBridge` now warns via `Log.w` when any of its
  three blocking @JvmStatic methods (`generateKey`, `signBytes`,
  `getAttestation`) is invoked on the main thread. Each can park its
  caller for hundreds of milliseconds to several seconds (Keystore
  hardware-backed keygen, Play Integrity service bind, signature
  IPC). The contract today is that the runtime drives them from a
  background isolate's OS thread, but nothing in this file actually
  checked it. The guard is cheap (one `Looper` identity compare),
  only logs on the assertion failure, and adds no behaviour change
  on the correct path — it just makes a regression visible the
  instant it happens, instead of letting it surface as a silent ANR.

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
