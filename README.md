🌐 [synheart.ai](https://synheart.ai) — Human State Interface (HSI) infrastructure for developers and AI systems.

# synheart-auth-flutter

[![Pub Version](https://img.shields.io/pub/v/synheart_auth.svg)](https://pub.dev/packages/synheart_auth)
[![Flutter](https://img.shields.io/badge/flutter-%3E%3D3.10.0-blue.svg)](https://flutter.dev)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)


> **Source-available.** This repository is open for reading, auditing, and
> filing issues. We do **not** accept pull requests — see
> [CONTRIBUTING.md](CONTRIBUTING.md) for the rationale and how to contribute
> via issues. Security reports go through [SECURITY.md](SECURITY.md).
Flutter plugin for Synheart device authentication. Provides hardware-backed ECDSA P-256 device identity and request signing via platform channels to the native iOS and Android SDKs.

> **Architecture**: This is a thin Dart wrapper — all cryptographic operations, key storage, and registration logic run natively on-device (iOS Secure Enclave / Android Keystore).

## Repository Structure

| Repository | Purpose |
|------------|---------|
| [synheart-auth](https://github.com/synheart-ai/synheart-auth) | RFC and specification |
| [synheart-auth-flutter](https://github.com/synheart-ai/synheart-auth-flutter) | Flutter plugin (this repository) |
| [synheart-auth-kotlin](https://github.com/synheart-ai/synheart-auth-kotlin) | Android/Kotlin native SDK |
| [synheart-auth-swift](https://github.com/synheart-ai/synheart-auth-swift) | iOS/Swift native SDK |

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  synheart_auth: ^0.1.8
```

Or:

```bash
flutter pub add synheart_auth
```

### Native SDK requirement

The plugin depends on the native Synheart Auth SDKs to do the actual
crypto. They are published separately:

- **Android**: [synheart-auth-kotlin](https://github.com/synheart-ai/synheart-auth-kotlin) — resolved automatically from Maven Central as `ai.synheart:synheart-auth:0.1.3`. Nothing to do in your app.
- **iOS**: [synheart-auth-swift](https://github.com/synheart-ai/synheart-auth-swift) — **requires a line in your Podfile.** The pod is not on CocoaPods trunk, so although this plugin's podspec declares the `SynheartAuth` dependency, it cannot be resolved unless your host Podfile points at the git source:

  ```ruby
  pod 'SynheartAuth',
    :git => 'https://github.com/synheart-ai/synheart-auth-swift.git',
    :tag => 'v0.1.1'
  ```

## Quick Start

```dart
import 'package:synheart_auth/synheart_auth.dart';

// 1. Configure once at app launch
await SynheartAuth.instance.configure('https://api.synheart.ai/auth');

// 2. Sign every HTTP request (registration is performed by
//    the Synheart runtime; this Flutter shell only signs).
final headers = await SynheartAuth.instance.signRequest(
  appId: 'com.myapp',
  method: 'POST',
  path: '/ingest/v1/hsi',
  bodyBytes: utf8.encode(jsonBody),
);
// headers contains all 6 auth headers — add to your HTTP request
```

> **Registration runs in the runtime, not this plugin.** The
> `registerDevice` and `rotateKey` methods on this Flutter plugin
> currently throw `UnsupportedError`; device registration and key
> rotation are driven by the Synheart runtime via the
> [Synheart Core SDK](https://github.com/synheart-ai/synheart-core-flutter).
> Use this plugin standalone only when you need to **sign** requests
> against a runtime-registered device key.

## API Reference

### `SynheartAuth`

| Method | Description |
|--------|-------------|
| `configure(baseUrl)` | Set the auth service URL. Must be called first. |
| `isRegistered(appId)` | Check if device is registered for this app. |
| `signRequest(...)` | Sign an HTTP request. Returns `SignedHeaders` with all 6 auth headers. |
| `getDeviceId(appId)` | Get the device ID, or null if not registered. |
| `resetDeviceIdentity(appId)` | Delete all local auth state. |
| `correctClockSkew(serverTimestamp)` | Correct clock offset using server timestamp. |
| `registerDevice(appId)` | **Throws `UnsupportedError`** — registration runs in the Synheart runtime. |
| `rotateKey(appId)` | **Throws `UnsupportedError`** — key rotation runs in the Synheart runtime. |

### Error Handling

All errors are subclasses of `SynheartAuthError`:

| Error | Description |
|-------|-------------|
| `NetworkError` | Network connectivity failure |
| `ChallengeExpired` | Registration challenge timed out |
| `AttestationUnavailable` | No hardware attestation could be produced (see below) |
| `KeyInvalidated` | Device key was invalidated (biometric change, etc.) |
| `ClockSkew` | Client/server clock difference exceeds threshold |
| `AlreadyRegistered` | Device already registered for this app |
| `NotRegistered` | Device not yet registered |
| `NotConfigured` | `configure()` not called |
| `RegistrationInProgress` | A registration call is already in flight |
| `ServerError` | Server returned an error response |
| `CryptoError` | Native crypto operation failed |
| `StorageError` | Persistent state read/write failed |
| `InvalidStateTransition` | Lifecycle violation (see `DeviceAuthState`) |

#### Attestation failures

`AttestationUnavailable` means no hardware attestation material could be
produced. On Android the plugin also classifies *why*, so the runtime can tell
a blip apart from a dead end. The reason travels natively to
synheart-core-runtime rather than on the Dart error, but it is the signal
behind retry behaviour you may observe:

| Reason | Retryable | Cause |
|--------|-----------|-------|
| `transient` | Yes, shortly | Network error, Play server unavailable, service binding failure |
| `timeout` | Yes, shortly | Play Integrity did not answer inside the 30-second cap |
| `quota` | Yes, later | Rate limited (`TOO_MANY_REQUESTS`) |
| `unsupported` | No | Device can never attest — Play Store/Services missing, outdated, or no account; also a missing or R8-stripped Play Integrity artifact |
| `misconfigured` | No, needs a developer | Play Console linkage, cloud project number, or nonce construction |
| `unknown` | No | Unrecognized failure; not guessed at either way |

These tokens are a contract with `AttestationReason` in
synheart-core-runtime. Adding one is safe — the Rust side degrades anything
unrecognized to `unknown` — but renaming one is a breaking change.

## Integration with synheart-core

synheart-auth implements the `AuthProvider` interface from synheart-core-flutter:

```dart
import 'package:synheart_core/synheart_core.dart';
import 'package:synheart_auth/synheart_auth.dart';

class DeviceAuthProvider implements AuthProvider {
  final String appId;
  DeviceAuthProvider(this.appId);

  @override
  Future<Map<String, String>> signRequest({
    required String method,
    required String path,
    required Uint8List bodyBytes,
  }) async {
    final signed = await SynheartAuth.instance.signRequest(
      appId: appId,
      method: method,
      path: path,
      bodyBytes: bodyBytes,
    );
    return signed.toMap();
  }

  @override
  Future<bool> onAuthError({
    required int statusCode,
    required Map<String, String> responseHeaders,
  }) async {
    // Handle clock skew, key rotation, etc.
    return false;
  }
}
```

## Testing

```bash
flutter test
```

The SDK supports test injection via `SynheartAuth.forTesting(bridge:)`.

## Not a Medical Device

This SDK is intended for wellness and research use only. It is not a medical device, is not intended to diagnose, treat, cure, or prevent any disease or condition, and has not been evaluated by the FDA or any other regulatory body.

## License

Apache License 2.0 — see [LICENSE](LICENSE).