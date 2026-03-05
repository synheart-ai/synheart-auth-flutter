import 'package:flutter_test/flutter_test.dart';
import 'package:synheart_auth/synheart_auth.dart';

void main() {
  group('SynheartAuthError', () {
    test('NetworkError has message', () {
      const error = NetworkError('Connection refused');
      expect(error.message, 'Connection refused');
      expect(error, isA<SynheartAuthError>());
    });

    test('ChallengeExpired has fixed message', () {
      const error = ChallengeExpired();
      expect(error.message, 'Challenge has expired');
    });

    test('ServerError has code and message', () {
      const error = ServerError(code: 'RATE_LIMIT', serverMessage: 'Too many requests');
      expect(error.message, contains('RATE_LIMIT'));
      expect(error.message, contains('Too many requests'));
    });

    test('InvalidStateTransition captures from/to', () {
      const error = InvalidStateTransition(from: 'unregistered', to: 'registered');
      expect(error.from, 'unregistered');
      expect(error.to, 'registered');
      expect(error.message, contains('unregistered'));
      expect(error.message, contains('registered'));
    });

    test('toString includes message', () {
      const error = NotConfigured();
      expect(error.toString(), contains('not been configured'));
    });

    test('fromCode maps NETWORK_ERROR', () {
      final error = SynheartAuthError.fromCode('NETWORK_ERROR', 'timeout');
      expect(error, isA<NetworkError>());
      expect(error.message, 'timeout');
    });

    test('fromCode maps CLOCK_SKEW', () {
      final error = SynheartAuthError.fromCode('CLOCK_SKEW');
      expect(error, isA<ClockSkew>());
    });

    test('fromCode maps NOT_CONFIGURED', () {
      final error = SynheartAuthError.fromCode('NOT_CONFIGURED');
      expect(error, isA<NotConfigured>());
    });

    test('fromCode maps ALREADY_REGISTERED', () {
      final error = SynheartAuthError.fromCode('ALREADY_REGISTERED');
      expect(error, isA<AlreadyRegistered>());
    });

    test('fromCode maps NOT_REGISTERED', () {
      final error = SynheartAuthError.fromCode('NOT_REGISTERED');
      expect(error, isA<NotRegistered>());
    });

    test('fromCode maps CRYPTO_ERROR', () {
      final error = SynheartAuthError.fromCode('CRYPTO_ERROR', 'bad key');
      expect(error, isA<CryptoError>());
      expect(error.message, 'bad key');
    });

    test('fromCode falls back to ServerError for unknown codes', () {
      final error = SynheartAuthError.fromCode('CUSTOM_CODE', 'custom msg');
      expect(error, isA<ServerError>());
    });
  });
}
