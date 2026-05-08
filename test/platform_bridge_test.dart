import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:synheart_auth/synheart_auth.dart';
// ignore: implementation_imports — `forTesting` accepts a `PlatformBridge`,
// which is the package's documented test-injection seam.
import 'package:synheart_auth/src/internal/platform_bridge.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late MethodChannel channel;
  late PlatformBridge bridge;
  late List<MethodCall> log;

  setUp(() {
    channel = const MethodChannel('ai.synheart.auth');
    bridge = PlatformBridge(channel: channel);
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
      throw PlatformException(code: code, message: message);
    });
  }

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  group('PlatformBridge', () {
    test('configure sends baseUrl', () async {
      mockHandler((_) => null);
      await bridge.configure('https://api.synheart.ai/auth');
      expect(log.single.method, 'configure');
      expect(log.single.arguments, {'baseUrl': 'https://api.synheart.ai/auth'});
    });

    test('isRegistered returns boolean', () async {
      mockHandler((_) => true);
      final result = await bridge.isRegistered('com.test.app');
      expect(result, isTrue);
      expect(log.single.method, 'isRegistered');
    });

    test('registerDevice throws UnsupportedError (handled by core-runtime)',
        () async {
      expect(
        () => bridge.registerDevice('com.test.app'),
        throwsA(isA<UnsupportedError>()),
      );
    });

    test('signRequest sends all arguments', () async {
      mockHandler((_) => {
            'appId': 'com.test.app',
            'deviceId': 'device-123',
            'signature': 'sig-abc',
            'timestamp': '2026-01-01T00:00:00Z',
            'nonce': 'uuid-123',
            'signatureVersion': '1',
          });

      final result = await bridge.signRequest(
        appId: 'com.test.app',
        method: 'POST',
        path: '/v1/data',
        bodyBytes: Uint8List.fromList([1, 2, 3]),
      );
      expect(result['signature'], 'sig-abc');

      final args = log.single.arguments as Map;
      expect(args['appId'], 'com.test.app');
      expect(args['method'], 'POST');
      expect(args['path'], '/v1/data');
      expect(args['bodyBytes'], isNotNull);
    });

    test('signRequest without body omits bodyBytes', () async {
      mockHandler((_) => {
            'appId': 'a',
            'deviceId': 'd',
            'signature': 's',
            'timestamp': 't',
            'nonce': 'n',
            'signatureVersion': '1',
          });

      await bridge.signRequest(
        appId: 'a',
        method: 'GET',
        path: '/v1/health',
      );

      final args = log.single.arguments as Map;
      expect(args.containsKey('bodyBytes'), isFalse);
    });

    test('getDeviceId returns nullable string', () async {
      mockHandler((_) => 'device-xyz');
      final result = await bridge.getDeviceId('com.test.app');
      expect(result, 'device-xyz');
    });

    test('getDeviceId returns null when not registered', () async {
      mockHandler((_) => null);
      final result = await bridge.getDeviceId('com.test.app');
      expect(result, isNull);
    });

    test('rotateKey throws UnsupportedError (handled by core-runtime)',
        () async {
      expect(
        () => bridge.rotateKey('com.test.app'),
        throwsA(isA<UnsupportedError>()),
      );
    });

    test('resetDeviceIdentity sends appId', () async {
      mockHandler((_) => null);
      await bridge.resetDeviceIdentity('com.test.app');
      expect(log.single.method, 'resetDeviceIdentity');
      expect(log.single.arguments, {'appId': 'com.test.app'});
    });

    test('correctClockSkew sends timestamp', () async {
      mockHandler((_) => null);
      await bridge.correctClockSkew(1709312345.0);
      expect(log.single.method, 'correctClockSkew');
      expect(
        (log.single.arguments as Map)['serverTimestamp'],
        1709312345.0,
      );
    });

    test('platform error maps to SynheartAuthError', () async {
      mockError('NOT_REGISTERED', 'Not registered');
      expect(
        () => bridge.signRequest(appId: 'a', method: 'GET', path: '/'),
        throwsA(isA<NotRegistered>()),
      );
    });

    test('platform error maps CLOCK_SKEW on signRequest', () async {
      mockError('CLOCK_SKEW', 'Clock skew');
      expect(
        () => bridge.signRequest(appId: 'a', method: 'GET', path: '/'),
        throwsA(isA<ClockSkew>()),
      );
    });

    test('platform error maps NETWORK_ERROR on signRequest', () async {
      mockError('NETWORK_ERROR', 'Connection refused');
      expect(
        () => bridge.signRequest(appId: 'a', method: 'GET', path: '/'),
        throwsA(isA<NetworkError>()),
      );
    });
  });
}
