import 'dart:typed_data';

import 'package:flutter/services.dart';

import '../models/auth_error.dart';

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
    final result =
        await _invoke<Map>('registerDevice', {'appId': appId});
    return Map<String, dynamic>.from(result ?? {});
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
    final result = await _invoke<Map>('rotateKey', {'appId': appId});
    return Map<String, dynamic>.from(result ?? {});
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
      final result = await _channel.invokeMethod<T>(method, args);
      return result;
    } on PlatformException catch (e) {
      throw SynheartAuthError.fromCode(e.code, e.message);
    }
  }
}
