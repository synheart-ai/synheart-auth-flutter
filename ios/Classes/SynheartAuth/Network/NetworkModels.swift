import Foundation

// MARK: - API Envelope

/// Generic wrapper for Synheart API responses: {"success":true,"data":{...}}
struct ApiEnvelope<T: Decodable>: Decodable {
    let success: Bool?
    let data: T?

    // Also support flat (unwrapped) responses for backwards compatibility
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.success = try container.decodeIfPresent(Bool.self, forKey: .success)
        self.data = try container.decodeIfPresent(T.self, forKey: .data)
    }

    enum CodingKeys: String, CodingKey {
        case success, data
    }
}

// MARK: - Challenge

struct ChallengeRequest: Codable {
    let appId: String

    enum CodingKeys: String, CodingKey {
        case appId = "app_id"
    }
}

/// Internal model matching the API's data payload.
///
/// Supports current auth service fields (`challenge_id`, `challenge_nonce`, `expires_at`)
/// and legacy single `challenge` string (see SDK_DART_AUTH_SEQUENCE.md).
struct ChallengeDataPayload: Decodable {
    let challenge: String?
    let challengeId: String?
    let challengeNonce: String?
    let expiresIn: Int?
    let expiresAt: String?

    enum CodingKeys: String, CodingKey {
        case challenge
        case challengeId = "challenge_id"
        case challengeNonce = "challenge_nonce"
        case expiresIn = "expires_in"
        case expiresAt = "expires_at"
    }

    /// Value used for registration / attestation nonce input (legacy `challenge` or nonce/id).
    var resolvedChallengeMaterial: String {
        if let c = challenge, !c.isEmpty { return c }
        if let n = challengeNonce, !n.isEmpty { return n }
        if let id = challengeId, !id.isEmpty { return id }
        return ""
    }
}

struct ChallengeResponse: Codable {
    let challenge: String
    let expiresAt: String

    enum CodingKeys: String, CodingKey {
        case challenge
        case expiresAt = "expires_at"
    }

    /// Parse from API envelope or flat response
    static func fromApiData(_ data: Data) throws -> ChallengeResponse {
        let decoder = JSONDecoder()
        // Try envelope format first
        if let envelope = try? decoder.decode(ApiEnvelope<ChallengeDataPayload>.self, from: data),
           let payload = envelope.data {
            let material = payload.resolvedChallengeMaterial
            guard !material.isEmpty else {
                throw DecodingError.dataCorrupted(
                    DecodingError.Context(
                        codingPath: [],
                        debugDescription: "No challenge, challenge_nonce, or challenge_id in challenge response"
                    )
                )
            }
            let expiresAt: String
            if let ea = payload.expiresAt {
                expiresAt = ea
            } else if let ei = payload.expiresIn {
                expiresAt = ISO8601DateFormatter().string(from: Date().addingTimeInterval(TimeInterval(ei)))
            } else {
                expiresAt = ISO8601DateFormatter().string(from: Date().addingTimeInterval(300))
            }
            return ChallengeResponse(challenge: material, expiresAt: expiresAt)
        }
        // Flat JSON without envelope: new fields or legacy `challenge`
        if let flat = try? decoder.decode(ChallengeDataPayload.self, from: data) {
            let material = flat.resolvedChallengeMaterial
            if !material.isEmpty {
                let expiresAt: String
                if let ea = flat.expiresAt {
                    expiresAt = ea
                } else if let ei = flat.expiresIn {
                    expiresAt = ISO8601DateFormatter().string(from: Date().addingTimeInterval(TimeInterval(ei)))
                } else {
                    expiresAt = ISO8601DateFormatter().string(from: Date().addingTimeInterval(300))
                }
                return ChallengeResponse(challenge: material, expiresAt: expiresAt)
            }
        }
        // Legacy flat: { "challenge", "expires_at" }
        return try decoder.decode(ChallengeResponse.self, from: data)
    }
}

// MARK: - Register

struct RegisterRequest: Codable {
    let appId: String
    let challenge: String
    let publicKey: String
    let attestation: String?
    let deviceMetadata: DeviceMetadata?

    enum CodingKeys: String, CodingKey {
        case appId = "app_id"
        case challenge
        case publicKey = "public_key"
        case attestation
        case deviceMetadata = "device_metadata"
    }
}

struct DeviceMetadata: Codable {
    let platform: String
    let osVersion: String?
    let model: String?
    let secureEnclave: Bool?

    enum CodingKeys: String, CodingKey {
        case platform
        case osVersion = "os_version"
        case model
        case secureEnclave = "secure_enclave"
    }
}

/// Internal model for parsing the register response payload
struct RegisterDataPayload: Decodable {
    let deviceId: String
    let appId: String?
    let platform: String?
    let registered: Bool?
    let status: String?

    enum CodingKeys: String, CodingKey {
        case deviceId = "device_id"
        case appId = "app_id"
        case platform
        case registered
        case status
    }
}

struct RegisterResponse: Codable {
    let deviceId: String
    let status: String

    enum CodingKeys: String, CodingKey {
        case deviceId = "device_id"
        case status
    }

    static func fromApiData(_ data: Data) throws -> RegisterResponse {
        let decoder = JSONDecoder()
        // Try envelope format: {"success":true,"data":{"device_id":"...","registered":true}}
        if let envelope = try? decoder.decode(ApiEnvelope<RegisterDataPayload>.self, from: data),
           let payload = envelope.data {
            let status: String
            if let s = payload.status {
                status = s
            } else if payload.registered == true {
                status = "success"
            } else {
                status = "failed"
            }
            return RegisterResponse(deviceId: payload.deviceId, status: status)
        }
        // Fallback: flat format
        return try decoder.decode(RegisterResponse.self, from: data)
    }
}

// MARK: - Rotate Key

struct RotateKeyRequest: Codable {
    let appId: String
    let deviceId: String
    let newPublicKey: String
    let oldKeySignature: String

    enum CodingKeys: String, CodingKey {
        case appId = "app_id"
        case deviceId = "device_id"
        case newPublicKey = "new_public_key"
        case oldKeySignature = "old_key_signature"
    }
}

struct RotateKeyResponse: Codable {
    let status: String

    static func fromApiData(_ data: Data) throws -> RotateKeyResponse {
        let decoder = JSONDecoder()
        if let envelope = try? decoder.decode(ApiEnvelope<RotateKeyResponse>.self, from: data),
           let payload = envelope.data {
            return payload
        }
        return try decoder.decode(RotateKeyResponse.self, from: data)
    }
}

// MARK: - Error

struct AuthErrorResponse: Decodable {
    let code: String
    let message: String
    let serverTimestamp: Double?

    init(code: String, message: String, serverTimestamp: Double? = nil) {
        self.code = code
        self.message = message
        self.serverTimestamp = serverTimestamp
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        // API uses error_code/error_description or legacy code/message
        self.code = (try? container.decode(String.self, forKey: .errorCode))
            ?? (try? container.decode(String.self, forKey: .code))
            ?? (try? container.decode(String.self, forKey: .error))
            ?? "UNKNOWN"
        self.message = (try? container.decode(String.self, forKey: .errorDescription))
            ?? (try? container.decode(String.self, forKey: .message))
            ?? "Unknown error"
        self.serverTimestamp = try? container.decode(Double.self, forKey: .serverTimestamp)
    }

    enum CodingKeys: String, CodingKey {
        case code
        case message
        case error
        case errorCode = "error_code"
        case errorDescription = "error_description"
        case serverTimestamp = "server_timestamp"
    }
}
