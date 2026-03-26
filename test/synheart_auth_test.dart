import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:synheart_auth/src/internal/platform_bridge.dart';
import 'package:synheart_auth/synheart_auth.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late MethodChannel channel;
  late SynheartAuth auth;
  late List<MethodCall> log;

  setUp(() {
    channel = const MethodChannel('ai.synheart.auth');
    auth = SynheartAuth.forTesting(bridge: PlatformBridge(channel: channel));
    log = [];
  });

  void mockHandler(dynamic Function(MethodCall call) handler) {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      log.add(call);
      return handler(call);
    });
  }

  void mockError(String code, String message) {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      log.add(call);
      throw PlatformException(code: code, message: message);
    });
  }

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  group('SynheartAuth', () {
    test('configure delegates to platform', () async {
      mockHandler((_) => null);
      await auth.configure('https://auth.synheart.io');
      expect(log.single.method, 'configure');
    });

    test('isRegistered returns false initially', () async {
      mockHandler((_) => false);
      expect(await auth.isRegistered('com.test.app'), isFalse);
    });

    test('registerDevice returns success result', () async {
      mockHandler((call) => switch (call.method) {
            'registerDevice' => {'status': 'success', 'deviceId': 'device-xyz-789'},
            _ => null,
          });

      final result = await auth.registerDevice('com.test.app');
      expect(result.status, RegistrationStatus.success);
      expect(result.deviceId, 'device-xyz-789');
    });

    test('registerDevice returns alreadyRegistered', () async {
      mockHandler((call) => switch (call.method) {
            'registerDevice' => {
              'status': 'alreadyRegistered',
              'deviceId': 'existing-device',
            },
            _ => null,
          });

      final result = await auth.registerDevice('com.test.app');
      expect(result.status, RegistrationStatus.alreadyRegistered);
      expect(result.deviceId, 'existing-device');
    });

    test('registerDevice maps already_registered snake_case', () async {
      mockHandler((call) => switch (call.method) {
            'registerDevice' => {
              'status': 'already_registered',
              'deviceId': 'existing-device',
            },
            _ => null,
          });

      final result = await auth.registerDevice('com.test.app');
      expect(result.status, RegistrationStatus.alreadyRegistered);
    });

    test('signRequest returns all 6 headers', () async {
      mockHandler((_) => {
            'appId': 'com.test.app',
            'deviceId': 'device-123',
            'signature': 'sig-base64',
            'timestamp': '2026-01-01T00:00:00Z',
            'nonce': 'uuid-nonce',
            'signatureVersion': '1',
          });

      final headers = await auth.signRequest(
        appId: 'com.test.app',
        method: 'GET',
        path: '/v1/health',
      );
      expect(headers.appId, 'com.test.app');
      expect(headers.deviceId, 'device-123');
      expect(headers.signature, 'sig-base64');
      expect(headers.timestamp, '2026-01-01T00:00:00Z');
      expect(headers.nonce, 'uuid-nonce');
      expect(headers.signatureVersion, '1');
    });

    test('signRequest with body passes bodyBytes', () async {
      mockHandler((_) => {
            'appId': 'a',
            'deviceId': 'd',
            'signature': 's',
            'timestamp': 't',
            'nonce': 'n',
            'signatureVersion': '1',
          });

      await auth.signRequest(
        appId: 'com.test.app',
        method: 'POST',
        path: '/v1/data',
        bodyBytes: Uint8List.fromList([1, 2, 3]),
      );

      final args = log.single.arguments as Map;
      expect(args['bodyBytes'], isNotNull);
    });

    test('signRequest throws NotRegistered on platform error', () async {
      mockError('NOT_REGISTERED', 'Not registered');
      expect(
        () => auth.signRequest(appId: 'a', method: 'GET', path: '/'),
        throwsA(isA<NotRegistered>()),
      );
    });

    test('getDeviceId returns device id', () async {
      mockHandler((_) => 'device-xyz');
      expect(await auth.getDeviceId('com.test.app'), 'device-xyz');
    });

    test('getDeviceId returns null when not registered', () async {
      mockHandler((_) => null);
      expect(await auth.getDeviceId('com.test.app'), isNull);
    });

    test('rotateKey returns success', () async {
      mockHandler((_) => {'status': 'success'});
      final result = await auth.rotateKey('com.test.app');
      expect(result.status, RotationStatus.success);
    });

    test('rotateKey returns failed on unknown status', () async {
      mockHandler((_) => {'status': 'error'});
      final result = await auth.rotateKey('com.test.app');
      expect(result.status, RotationStatus.failed);
    });

    test('resetDeviceIdentity delegates to platform', () async {
      mockHandler((_) => null);
      await auth.resetDeviceIdentity('com.test.app');
      expect(log.single.method, 'resetDeviceIdentity');
    });

    test('correctClockSkew delegates to platform', () async {
      mockHandler((_) => null);
      await auth.correctClockSkew(1709312345.0);
      expect(log.single.method, 'correctClockSkew');
      expect(
        (log.single.arguments as Map)['serverTimestamp'],
        1709312345.0,
      );
    });

    test('registration failure maps platform error', () async {
      mockError('NETWORK_ERROR', 'Connection refused');
      expect(
        () => auth.registerDevice('com.test.app'),
        throwsA(isA<NetworkError>()),
      );
    });

    test('rotation failure maps platform error', () async {
      mockError('NOT_REGISTERED', 'Not registered');
      expect(
        () => auth.rotateKey('com.test.app'),
        throwsA(isA<NotRegistered>()),
      );
    });
  });
}
