import 'auth_error.dart';

/// Device authentication state machine.
enum DeviceAuthState {
  unregistered('unregistered'),
  challengeReceived('challengeReceived'),
  keyReady('keyReady'),
  registering('registering'),
  registered('registered'),
  keyInvalid('keyInvalid');

  final String value;
  const DeviceAuthState(this.value);

  /// Whether transitioning to [next] is valid per the RFC state machine.
  bool canTransition(DeviceAuthState next) => switch ((this, next)) {
        (unregistered, challengeReceived) => true,
        (challengeReceived, keyReady) => true,
        (keyReady, registering) => true,
        (registering, registered) => true,
        (registering, unregistered) => true,
        (registered, registering) => true,
        (registered, keyInvalid) => true,
        (keyInvalid, unregistered) => true,
        _ => false,
      };

  /// Attempt a state transition, throwing if invalid.
  DeviceAuthState transition(DeviceAuthState next) {
    if (!canTransition(next)) {
      throw InvalidStateTransition(from: value, to: next.value);
    }
    return next;
  }

  /// Parse from a string value, returning null if unknown.
  static DeviceAuthState? fromValue(String value) {
    for (final state in DeviceAuthState.values) {
      if (state.value == value) return state;
    }
    return null;
  }
}
