/// Status of a device registration attempt.
enum RegistrationStatus { success, alreadyRegistered, failed }

/// Result of [SynheartAuth.registerDevice].
class RegistrationResult {
  final RegistrationStatus status;
  final String? deviceId;

  const RegistrationResult({required this.status, this.deviceId});
}

/// Status of a key rotation attempt.
enum RotationStatus { success, failed }

/// Result of [SynheartAuth.rotateKey].
class RotationResult {
  final RotationStatus status;

  const RotationResult({required this.status});
}

/// Headers to attach to every authenticated HTTP request.
class SignedHeaders {
  final String appId;
  final String deviceId;
  final String signature;
  final String timestamp;
  final String nonce;
  final String signatureVersion;

  const SignedHeaders({
    required this.appId,
    required this.deviceId,
    required this.signature,
    required this.timestamp,
    required this.nonce,
    this.signatureVersion = '1',
  });

  /// Returns headers as a map suitable for HTTP requests.
  Map<String, String> toMap() => {
        'X-App-ID': appId,
        'X-Device-ID': deviceId,
        'X-Synheart-Signature': signature,
        'X-Synheart-Timestamp': timestamp,
        'X-Synheart-Nonce': nonce,
        'X-Synheart-Sig-Version': signatureVersion,
      };

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is SignedHeaders &&
          appId == other.appId &&
          deviceId == other.deviceId &&
          signature == other.signature &&
          timestamp == other.timestamp &&
          nonce == other.nonce &&
          signatureVersion == other.signatureVersion;

  @override
  int get hashCode => Object.hash(
        appId,
        deviceId,
        signature,
        timestamp,
        nonce,
        signatureVersion,
      );
}
