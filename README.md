# synheart-auth-dart

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/synheart-ai/synheart-auth-dart)
[![Flutter](https://img.shields.io/badge/flutter-%3E%3D3.10.0-blue.svg)](https://flutter.dev)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

Flutter plugin for Synheart device authentication. Provides hardware-backed ECDSA P-256 device identity and request signing via platform channels to the native iOS and Android SDKs.

> **Architecture**: This is a thin Dart wrapper — all cryptographic operations, key storage, and registration logic run natively on-device (iOS Secure Enclave / Android Keystore). See [RFC-AUTH-MOBILE-0001](https://github.com/synheart-ai/synheart-auth/blob/main/docs/RFC-AUTH-MOBILE-0001.md).

## Repository Structure

| Repository | Purpose |
|------------|---------|
| [synheart-auth](https://github.com/synheart-ai/synheart-auth) | RFC and specification |
| [synheart-auth-dart](https://github.com/synheart-ai/synheart-auth-dart) | Flutter plugin (this repository) |
| [synheart-auth-kotlin](https://github.com/synheart-ai/synheart-auth-kotlin) | Android/Kotlin native SDK |
| [synheart-auth-swift](https://github.com/synheart-ai/synheart-auth-swift) | iOS/Swift native SDK |

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  synheart_auth:
    git:
      url: https://github.com/synheart-ai/synheart-auth-dart.git
      ref: main
```

## Quick Start

```dart
import 'package:synheart_auth/synheart_auth.dart';

// 1. Configure once at app launch
await SynheartAuth.instance.configure('https://auth.synheart.ai');

// 2. Register device (one-time)
final result = await SynheartAuth.instance.registerDevice('com.myapp');
print('Device ID: ${result.deviceId}');

// 3. Sign every HTTP request
final headers = await SynheartAuth.instance.signRequest(
  appId: 'com.myapp',
  method: 'POST',
  path: '/v1/ingest/hsi',
  bodyBytes: utf8.encode(jsonBody),
);
// headers contains all 6 auth headers — add to your HTTP request
```

## API Reference

### `SynheartAuth`

| Method | Description |
|--------|-------------|
| `configure(baseUrl)` | Set the auth service URL. Must be called first. |
| `isRegistered(appId)` | Check if device is registered for this app. |
| `registerDevice(appId)` | Register device with auth service. Idempotent. |
| `signRequest(...)` | Sign an HTTP request. Returns `SignedHeaders` with all 6 auth headers. |
| `getDeviceId(appId)` | Get the device ID, or null if not registered. |
| `rotateKey(appId)` | Rotate the device key. Old key signs new key as proof. |
| `resetDeviceIdentity(appId)` | Delete all local auth state. Device must re-register. |
| `correctClockSkew(serverTimestamp)` | Correct clock offset using server timestamp. |

### Error Handling

All errors are subclasses of `SynheartAuthError`:

| Error | Description |
|-------|-------------|
| `NetworkError` | Network connectivity failure |
| `ChallengeExpired` | Registration challenge timed out |
| `AttestationUnavailable` | Platform attestation not available |
| `KeyInvalidated` | Device key was invalidated (biometric change, etc.) |
| `ClockSkew` | Client/server clock difference exceeds threshold |
| `AlreadyRegistered` | Device already registered for this app |
| `NotRegistered` | Device not yet registered |
| `NotConfigured` | `configure()` not called |
| `ServerError` | Server returned an error response |

## Integration with synheart-core

synheart-auth implements the `AuthProvider` interface from synheart-core-dart:

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

## License

Apache License 2.0 — see [LICENSE](LICENSE).
