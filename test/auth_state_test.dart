import 'package:flutter_test/flutter_test.dart';
import 'package:synheart_auth/synheart_auth.dart';

void main() {
  group('DeviceAuthState', () {
    test('unregistered can transition to challengeReceived', () {
      expect(
        DeviceAuthState.unregistered.canTransition(DeviceAuthState.challengeReceived),
        isTrue,
      );
    });

    test('challengeReceived can transition to keyReady', () {
      expect(
        DeviceAuthState.challengeReceived.canTransition(DeviceAuthState.keyReady),
        isTrue,
      );
    });

    test('keyReady can transition to registering', () {
      expect(
        DeviceAuthState.keyReady.canTransition(DeviceAuthState.registering),
        isTrue,
      );
    });

    test('registering can transition to registered', () {
      expect(
        DeviceAuthState.registering.canTransition(DeviceAuthState.registered),
        isTrue,
      );
    });

    test('registering can transition to unregistered on failure', () {
      expect(
        DeviceAuthState.registering.canTransition(DeviceAuthState.unregistered),
        isTrue,
      );
    });

    test('registered can transition to registering for rotation', () {
      expect(
        DeviceAuthState.registered.canTransition(DeviceAuthState.registering),
        isTrue,
      );
    });

    test('registered can transition to keyInvalid', () {
      expect(
        DeviceAuthState.registered.canTransition(DeviceAuthState.keyInvalid),
        isTrue,
      );
    });

    test('keyInvalid can transition to unregistered', () {
      expect(
        DeviceAuthState.keyInvalid.canTransition(DeviceAuthState.unregistered),
        isTrue,
      );
    });

    test('invalid transition throws', () {
      expect(
        () => DeviceAuthState.unregistered.transition(DeviceAuthState.registered),
        throwsA(isA<InvalidStateTransition>()),
      );
    });

    test('unregistered cannot skip to registered', () {
      expect(
        DeviceAuthState.unregistered.canTransition(DeviceAuthState.registered),
        isFalse,
      );
    });

    test('transition returns new state', () {
      final next = DeviceAuthState.unregistered.transition(DeviceAuthState.challengeReceived);
      expect(next, DeviceAuthState.challengeReceived);
    });

    test('fromValue roundtrip', () {
      for (final state in DeviceAuthState.values) {
        expect(DeviceAuthState.fromValue(state.value), state);
      }
    });

    test('fromValue returns null for unknown', () {
      expect(DeviceAuthState.fromValue('nonexistent'), isNull);
    });
  });
}
