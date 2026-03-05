import 'package:flutter_test/flutter_test.dart';
import 'package:synheart_auth/synheart_auth.dart';

void main() {
  group('SignedHeaders', () {
    test('toMap returns all 6 headers', () {
      const headers = SignedHeaders(
        appId: 'com.test.app',
        deviceId: 'device-123',
        signature: 'sig-base64',
        timestamp: '2026-01-01T00:00:00Z',
        nonce: 'uuid-nonce',
        signatureVersion: '1',
      );
      final map = headers.toMap();
      expect(map.length, 6);
      expect(map['X-App-ID'], 'com.test.app');
      expect(map['X-Device-ID'], 'device-123');
      expect(map['X-Synheart-Signature'], 'sig-base64');
      expect(map['X-Synheart-Timestamp'], '2026-01-01T00:00:00Z');
      expect(map['X-Synheart-Nonce'], 'uuid-nonce');
      expect(map['X-Synheart-Sig-Version'], '1');
    });

    test('signatureVersion defaults to 1', () {
      const headers = SignedHeaders(
        appId: 'a',
        deviceId: 'd',
        signature: 's',
        timestamp: 't',
        nonce: 'n',
      );
      expect(headers.signatureVersion, '1');
    });

    test('equality works', () {
      const a = SignedHeaders(
        appId: 'a', deviceId: 'd', signature: 's',
        timestamp: 't', nonce: 'n',
      );
      const b = SignedHeaders(
        appId: 'a', deviceId: 'd', signature: 's',
        timestamp: 't', nonce: 'n',
      );
      expect(a, equals(b));
      expect(a.hashCode, b.hashCode);
    });

    test('inequality on different fields', () {
      const a = SignedHeaders(
        appId: 'a', deviceId: 'd', signature: 's',
        timestamp: 't', nonce: 'n1',
      );
      const b = SignedHeaders(
        appId: 'a', deviceId: 'd', signature: 's',
        timestamp: 't', nonce: 'n2',
      );
      expect(a, isNot(equals(b)));
    });
  });

  group('RegistrationResult', () {
    test('success result has deviceId', () {
      const result = RegistrationResult(
        status: RegistrationStatus.success,
        deviceId: 'device-xyz',
      );
      expect(result.status, RegistrationStatus.success);
      expect(result.deviceId, 'device-xyz');
    });

    test('failed result has no deviceId', () {
      const result = RegistrationResult(
        status: RegistrationStatus.failed,
      );
      expect(result.status, RegistrationStatus.failed);
      expect(result.deviceId, isNull);
    });

    test('alreadyRegistered status', () {
      const result = RegistrationResult(
        status: RegistrationStatus.alreadyRegistered,
        deviceId: 'existing-device',
      );
      expect(result.status, RegistrationStatus.alreadyRegistered);
    });
  });

  group('RotationResult', () {
    test('success', () {
      const result = RotationResult(status: RotationStatus.success);
      expect(result.status, RotationStatus.success);
    });

    test('failed', () {
      const result = RotationResult(status: RotationStatus.failed);
      expect(result.status, RotationStatus.failed);
    });
  });
}
