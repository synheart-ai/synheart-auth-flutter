/// All error types from RFC-AUTH-MOBILE-0001.
sealed class SynheartAuthError implements Exception {
  const SynheartAuthError();

  String get message;

  @override
  String toString() => 'SynheartAuthError: $message';

  /// Create the appropriate error subtype from a platform channel error code.
  factory SynheartAuthError.fromCode(String code, [String? msg]) {
    return switch (code) {
      'NETWORK_ERROR' => NetworkError(msg ?? 'Network error'),
      'CHALLENGE_EXPIRED' => const ChallengeExpired(),
      'ATTESTATION_UNAVAILABLE' => const AttestationUnavailable(),
      'KEY_INVALIDATED' => const KeyInvalidated(),
      'CLOCK_SKEW' => const ClockSkew(),
      'ALREADY_REGISTERED' => const AlreadyRegistered(),
      'NOT_REGISTERED' => const NotRegistered(),
      'NOT_CONFIGURED' => const NotConfigured(),
      'REGISTRATION_IN_PROGRESS' => const RegistrationInProgress(),
      'CRYPTO_ERROR' => CryptoError(msg ?? 'Crypto error'),
      'STORAGE_ERROR' => StorageError(msg ?? 'Storage error'),
      _ => ServerError(code: code, serverMessage: msg ?? 'Unknown error'),
    };
  }
}

class NetworkError extends SynheartAuthError {
  @override
  final String message;
  const NetworkError(this.message);
}

class ChallengeExpired extends SynheartAuthError {
  const ChallengeExpired();
  @override
  String get message => 'Challenge has expired';
}

class AttestationUnavailable extends SynheartAuthError {
  const AttestationUnavailable();
  @override
  String get message => 'Attestation unavailable on this device';
}

class KeyInvalidated extends SynheartAuthError {
  const KeyInvalidated();
  @override
  String get message => 'Signing key has been invalidated';
}

class ClockSkew extends SynheartAuthError {
  const ClockSkew();
  @override
  String get message => 'Client clock is too far from server time';
}

class AlreadyRegistered extends SynheartAuthError {
  const AlreadyRegistered();
  @override
  String get message => 'Device is already registered';
}

class NotRegistered extends SynheartAuthError {
  const NotRegistered();
  @override
  String get message => 'Device is not registered';
}

class NotConfigured extends SynheartAuthError {
  const NotConfigured();
  @override
  String get message => 'SDK has not been configured';
}

class RegistrationInProgress extends SynheartAuthError {
  const RegistrationInProgress();
  @override
  String get message => 'Registration is already in progress';
}

class ServerError extends SynheartAuthError {
  final String code;
  final String serverMessage;
  const ServerError({required this.code, required this.serverMessage});
  @override
  String get message => 'Server error [$code]: $serverMessage';
}

class CryptoError extends SynheartAuthError {
  @override
  final String message;
  const CryptoError(this.message);
}

class StorageError extends SynheartAuthError {
  @override
  final String message;
  const StorageError(this.message);
}

class InvalidStateTransition extends SynheartAuthError {
  final String from;
  final String to;
  const InvalidStateTransition({required this.from, required this.to});
  @override
  String get message => 'Invalid state transition from $from to $to';
}
