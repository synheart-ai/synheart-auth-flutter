import 'dart:typed_data';

import 'package:flutter/services.dart';

import 'internal/platform_bridge.dart';
import 'models/auth_error.dart';
import 'models/auth_models.dart';

/// Public facade for the Synheart device authentication SDK.
///
/// This is a thin Dart wrapper that delegates all crypto, storage, and
/// registration to the native iOS (Secure Enclave) and Android (Keystore)
/// implementations via platform channels.
///
/// Usage:
/// ```dart
/// // 1. Configure once at app launch
/// SynheartAuth.instance.configure('https://auth.synheart.ai');
///
/// // 2. Register device (once)
/// final result = await SynheartAuth.instance.registerDevice('com.myapp');
///
/// // 3. Sign every HTTP request
/// final headers = await SynheartAuth.instance.signRequest(
///   appId: 'com.myapp',
///   method: 'POST',
///   path: '/v1/data',
///   bodyBytes: utf8.encode(jsonBody),
/// );
/// ```
class SynheartAuth {
  final PlatformBridge _bridge;

  SynheartAuth._({PlatformBridge? bridge})
      : _bridge = bridge ?? PlatformBridge();

  /// Singleton instance.
  static final SynheartAuth instance = SynheartAuth._();

  /// Create an instance with a custom platform bridge (for testing).
  factory SynheartAuth.forTesting({required PlatformBridge bridge}) =>
      SynheartAuth._(bridge: bridge);

  /// Configure the SDK with the auth service base URL.
  /// Must be called before any other method.
  Future<void> configure(String baseUrl) => _bridge.configure(baseUrl);

  /// Check if a device is already registered for the given app.
  Future<bool> isRegistered(String appId) => _bridge.isRegistered(appId);

  /// Register this device with the Synheart auth service.
  ///
  /// Idempotent — if already registered, returns [RegistrationStatus.alreadyRegistered].
  Future<RegistrationResult> registerDevice(String appId) async {
    final result = await _bridge.registerDevice(appId);
    final statusStr = result['status'] as String? ?? 'failed';
    return RegistrationResult(
      status: _parseRegistrationStatus(statusStr),
      deviceId: result['deviceId'] as String?,
    );
  }

  /// Sign an HTTP request with device credentials.
  ///
  /// Returns [SignedHeaders] containing all 6 required auth headers.
  Future<SignedHeaders> signRequest({
    required String appId,
    required String method,
    required String path,
    Uint8List? bodyBytes,
  }) async {
    final result = await _bridge.signRequest(
      appId: appId,
      method: method,
      path: path,
      bodyBytes: bodyBytes,
    );
    return SignedHeaders(
      appId: result['appId'] as String,
      deviceId: result['deviceId'] as String,
      signature: result['signature'] as String,
      timestamp: result['timestamp'] as String,
      nonce: result['nonce'] as String,
      signatureVersion: result['signatureVersion'] as String? ?? '1',
    );
  }

  /// Get the device ID for the given app, or null if not registered.
  Future<String?> getDeviceId(String appId) => _bridge.getDeviceId(appId);

  /// Rotate the device key. The old key signs the new public key as proof of possession.
  Future<RotationResult> rotateKey(String appId) async {
    final result = await _bridge.rotateKey(appId);
    final statusStr = result['status'] as String? ?? 'failed';
    return RotationResult(
      status: statusStr == 'success'
          ? RotationStatus.success
          : RotationStatus.failed,
    );
  }

  /// Destructive: delete all local auth state for this app.
  /// The device will need to re-register.
  Future<void> resetDeviceIdentity(String appId) =>
      _bridge.resetDeviceIdentity(appId);

  /// Correct clock skew using a server-provided timestamp (seconds since epoch).
  ///
  /// Call this when you receive a CLOCK_SKEW error from the server.
  Future<void> correctClockSkew(double serverTimestamp) =>
      _bridge.correctClockSkew(serverTimestamp);

  RegistrationStatus _parseRegistrationStatus(String status) => switch (status) {
        'success' => RegistrationStatus.success,
        'alreadyRegistered' || 'already_registered' =>
          RegistrationStatus.alreadyRegistered,
        _ => RegistrationStatus.failed,
      };
}
