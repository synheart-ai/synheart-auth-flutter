import 'dart:developer' as developer;
import 'dart:typed_data';

import 'package:flutter/foundation.dart' show kDebugMode;
import 'package:flutter/services.dart';

import '../models/auth_error.dart';

const bool _kAuthDiagnostics =
    bool.fromEnvironment('SYNHEART_AUTH_DIAGNOSTICS', defaultValue: true);

bool get _authDiagEnabled => kDebugMode && _kAuthDiagnostics;

String _preview(String s, [int n = 16]) =>
    s.length <= n ? s : '${s.substring(0, n)}...';

Map<String, Object?> _redactArgs(Map<String, dynamic>? args) {
  if (args == null) return const {};
  final out = <String, Object?>{};
  for (final e in args.entries) {
    final k = e.key;
    final v = e.value;
    if (v is Uint8List) {
      out[k] = '<bytes len=${v.length}>';
    } else if (v is String && k.toLowerCase().contains('baseurl')) {
      out[k] = v;
    } else {
      out[k] = v;
    }
  }
  return out;
}

/// Platform channel bridge to native iOS/Android auth SDKs.
///
/// All crypto, storage, and registration is performed natively.
/// This class translates Dart calls into MethodChannel invocations.
class PlatformBridge {
  final MethodChannel _channel;

  PlatformBridge({MethodChannel? channel})
      : _channel = channel ?? const MethodChannel('ai.synheart.auth');

  // -- Configuration --

  Future<void> configure(String baseUrl) async {
    await _invoke('configure', {'baseUrl': baseUrl});
  }

  // -- Registration --

  Future<bool> isRegistered(String appId) async {
    final result = await _invoke<bool>('isRegistered', {'appId': appId});
    return result ?? false;
  }

  Future<Map<String, dynamic>> registerDevice(String appId) async {
    // Runtime-only networking policy:
    // Device registration must be performed by synheart-core-runtime, not SDK APIs.
    throw UnsupportedError(
      'registerDevice is disabled in synheart_auth. '
      'Use synheart_core_runtime device registration flow.',
    );
  }

  // -- Signing --

  Future<Map<String, dynamic>> signRequest({
    required String appId,
    required String method,
    required String path,
    Uint8List? bodyBytes,
  }) async {
    final result = await _invoke<Map>('signRequest', {
      'appId': appId,
      'method': method,
      'path': path,
      if (bodyBytes != null) 'bodyBytes': bodyBytes,
    });
    return Map<String, dynamic>.from(result ?? {});
  }

  // -- Device ID --

  Future<String?> getDeviceId(String appId) async {
    return await _invoke<String?>('getDeviceId', {'appId': appId});
  }

  // -- Key Rotation --

  Future<Map<String, dynamic>> rotateKey(String appId) async {
    // Runtime-only networking policy:
    // Key rotation is an outbound auth operation and must run via core-runtime.
    throw UnsupportedError(
      'rotateKey is disabled in synheart_auth. '
      'Use synheart_core_runtime key management/rotation flow.',
    );
  }

  // -- Reset --

  Future<void> resetDeviceIdentity(String appId) async {
    await _invoke('resetDeviceIdentity', {'appId': appId});
  }

  // -- Clock Skew --

  Future<void> correctClockSkew(double serverTimestamp) async {
    await _invoke(
        'correctClockSkew', {'serverTimestamp': serverTimestamp});
  }

  // -- Private --

  Future<T?> _invoke<T>(String method, [Map<String, dynamic>? args]) async {
    try {
      if (_authDiagEnabled) {
        developer.log(
          '[SynheartAuth] → $method ${_redactArgs(args)}',
          name: 'synheart_auth',
        );
      }
      final result = await _channel.invokeMethod<T>(method, args);
      if (_authDiagEnabled) {
        // Avoid dumping full payloads (signatures/tokens). Log only high-signal metadata.
        Object? meta = result;
        if (result is Map) {
          final m = Map<String, Object?>.from(result as Map);
          if (method == 'signRequest') {
            meta = {
              'appId': m['appId'],
              'deviceId': m['deviceId'],
              'timestamp': m['timestamp'],
              'noncePrefix': m['nonce'] is String ? _preview(m['nonce'] as String) : null,
              'signatureLen': (m['signature'] is String) ? (m['signature'] as String).length : null,
              'signatureVersion': m['signatureVersion'],
            };
          } else if (method == 'registerDevice') {
            meta = {
              'status': m['status'],
              'deviceId': m['deviceId'],
            };
          }
        }
        developer.log(
          '[SynheartAuth] ← $method result=$meta',
          name: 'synheart_auth',
        );
      }
      return result;
    } on PlatformException catch (e) {
      if (_authDiagEnabled) {
        developer.log(
          '[SynheartAuth] ← $method PlatformException code=${e.code} message=${e.message}',
          name: 'synheart_auth',
          error: e,
        );
      }
      throw SynheartAuthError.fromCode(e.code, e.message);
    }
  }
}
