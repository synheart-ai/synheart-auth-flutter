import Foundation
import Security

// ── RFC-CORE-0008: C-callable crypto bridge ─────────────────────────────
//
// These functions are exported with C linkage using @_cdecl so the Dart SDK
// can look them up via DynamicLibrary.process() and pass them as function
// pointers to Rust Core's SynheartSdkCryptoCallbacks struct.
//
// Rust Core calls these synchronously during:
//   - Device registration (generate_key, get_attestation, sign_bytes)
//   - Proof header generation (sign_bytes, key_exists)
//
// Memory contract: returned C strings are allocated with strdup() and MUST
// be freed by the caller (Rust frees via CString::from_raw).

// Shared KeyManager instance — initialized once.
private let sharedKeyManager = KeyManager()

/// Generate a P-256 key pair for the given device_id.
///
/// Returns a C string containing JSON: `{"x":"<base64url>","y":"<base64url>"}`
/// where x and y are the uncompressed P-256 public key coordinates.
/// Returns NULL on failure.
@_cdecl("synheart_native_generate_key")
public func synheartNativeGenerateKey(_ deviceId: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let deviceId = deviceId else { return nil }
    let appId = String(cString: deviceId)

    do {
        // Generate Secure Enclave / software P-256 key.
        // Returns uncompressed X9.62 public key (65 bytes: 0x04 || x || y).
        let publicKeyData = try sharedKeyManager.generateKeyPair(appId: appId)

        guard publicKeyData.count == 65, publicKeyData[0] == 0x04 else {
            AuthLogger.shared.error("Unexpected public key format: \(publicKeyData.count) bytes")
            return nil
        }

        // Extract x, y coordinates (32 bytes each) and encode as base64url.
        let x = publicKeyData[1...32]
        let y = publicKeyData[33...64]
        let xB64 = base64urlEncode(x)
        let yB64 = base64urlEncode(y)

        let json = "{\"x\":\"\(xB64)\",\"y\":\"\(yB64)\"}"
        return strdup(json)
    } catch {
        AuthLogger.shared.error("synheart_native_generate_key failed: \(error)")
        return nil
    }
}

/// Sign raw bytes with the device key identified by device_id.
///
/// Rust passes the exact bytes to sign (it has already canonicalized them).
/// Returns a C string containing base64url encoding of the raw 64-byte
/// R||S ECDSA signature. Returns NULL on failure.
///
/// NOTE: iOS SecKeyCreateSignature returns DER-encoded signatures. We convert
/// DER → raw R||S (64 bytes) because the Rust JWS compact serialization
/// expects raw R||S per RFC 7515 / ES256.
@_cdecl("synheart_native_sign_bytes")
public func synheartNativeSignBytes(
    _ deviceId: UnsafePointer<CChar>?,
    _ data: UnsafePointer<UInt8>?,
    _ dataLen: Int
) -> UnsafeMutablePointer<CChar>? {
    guard let deviceId = deviceId, let data = data, dataLen > 0 else { return nil }
    let appId = String(cString: deviceId)

    do {
        let inputData = Data(bytes: data, count: dataLen)

        // Sign using SecKeyCreateSignature (ecdsaSignatureMessageX962SHA256).
        // Returns DER-encoded ECDSA signature.
        let derSignature = try sharedKeyManager.sign(data: inputData, appId: appId)

        // Convert DER to raw R||S (64 bytes for P-256).
        guard let rawRS = derToRawRS(derSignature) else {
            AuthLogger.shared.error("DER→R||S conversion failed")
            return nil
        }

        let b64 = base64urlEncode(rawRS)
        return strdup(b64)
    } catch {
        AuthLogger.shared.error("synheart_native_sign_bytes failed: \(error)")
        return nil
    }
}

/// Get platform attestation for the given device_id and challenge hash.
///
/// Returns JSON: `{"format":"apple-appattest","blob":"<base64>"}` or
/// `{"format":"none","blob":""}` if attestation is unavailable.
/// Returns NULL on failure.
@_cdecl("synheart_native_get_attestation")
public func synheartNativeGetAttestation(
    _ deviceId: UnsafePointer<CChar>?,
    _ hashPtr: UnsafePointer<UInt8>?,
    _ hashLen: Int
) -> UnsafeMutablePointer<CChar>? {
    // Attestation is best-effort. If App Attest is unavailable (simulator,
    // older devices), return format:"none" so Rust can proceed without it.
    let json = "{\"format\":\"none\",\"blob\":\"\"}"
    return strdup(json)
    // TODO: Implement DCAppAttestService.attestKey when available.
    // This requires the key to be generated via DCAppAttestService.generateKey
    // rather than SecKeyCreateRandomKey, which is a separate flow.
}

/// Check if a key exists for the given device_id.
/// Returns 1 if exists, 0 if not.
@_cdecl("synheart_native_key_exists")
public func synheartNativeKeyExists(_ deviceId: UnsafePointer<CChar>?) -> Int32 {
    guard let deviceId = deviceId else { return 0 }
    let appId = String(cString: deviceId)
    return sharedKeyManager.hasKey(appId: appId) ? 1 : 0
}

/// Delete the key for the given device_id.
/// Returns 0 on success, 1 on failure.
@_cdecl("synheart_native_delete_key")
public func synheartNativeDeleteKey(_ deviceId: UnsafePointer<CChar>?) -> Int32 {
    guard let deviceId = deviceId else { return 1 }
    let appId = String(cString: deviceId)
    sharedKeyManager.deleteKey(appId: appId)
    return 0
}

/// Store secure value for `(service, key)`. Returns 0 on success, non-zero on failure.
@_cdecl("synheart_native_secure_store")
public func synheartNativeSecureStore(
    _ service: UnsafePointer<CChar>?,
    _ key: UnsafePointer<CChar>?,
    _ value: UnsafePointer<CChar>?
) -> Int32 {
    guard let service, let key, let value else { return 1 }
    let serviceStr = String(cString: service)
    let keyStr = String(cString: key)
    let valueStr = String(cString: value)
    let ok = keychainStore(service: serviceStr, account: keyStr, value: valueStr)
    return ok ? 0 : 1
}

/// Load secure value for `(service, key)`. Returns strdup'd C string or nil.
@_cdecl("synheart_native_secure_load")
public func synheartNativeSecureLoad(
    _ service: UnsafePointer<CChar>?,
    _ key: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar>? {
    guard let service, let key else { return nil }
    let serviceStr = String(cString: service)
    let keyStr = String(cString: key)
    guard let value = keychainLoad(service: serviceStr, account: keyStr) else {
        return nil
    }
    return strdup(value)
}

/// Delete secure value for `(service, key)`. Returns 0 on success, non-zero on failure.
@_cdecl("synheart_native_secure_delete")
public func synheartNativeSecureDelete(
    _ service: UnsafePointer<CChar>?,
    _ key: UnsafePointer<CChar>?
) -> Int32 {
    guard let service, let key else { return 1 }
    let serviceStr = String(cString: service)
    let keyStr = String(cString: key)
    let ok = keychainDelete(service: serviceStr, account: keyStr)
    return ok ? 0 : 1
}

// MARK: - Helpers

/// Base64url encode (no padding) per RFC 4648 §5.
private func base64urlEncode(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

/// Convert DER-encoded ECDSA signature to raw R||S (64 bytes for P-256).
///
/// DER format: 30 <len> 02 <rLen> <r> 02 <sLen> <s>
/// Output: R (32 bytes, left-padded) || S (32 bytes, left-padded)
private func derToRawRS(_ der: Data) -> Data? {
    guard der.count > 8 else { return nil }
    var offset = 0

    // 0x30 SEQUENCE
    guard der[offset] == 0x30 else { return nil }
    offset += 1

    // Total length (skip, we have the data)
    if der[offset] & 0x80 != 0 {
        offset += Int(der[offset] & 0x7F) + 1
    } else {
        offset += 1
    }

    // Parse R
    guard der[offset] == 0x02 else { return nil }
    offset += 1
    let rLen = Int(der[offset])
    offset += 1
    var r = der[offset..<(offset + rLen)]
    offset += rLen

    // Parse S
    guard der[offset] == 0x02 else { return nil }
    offset += 1
    let sLen = Int(der[offset])
    offset += 1
    var s = der[offset..<(offset + sLen)]
    offset += sLen

    // Strip leading zero padding (DER uses a leading 0x00 for sign)
    if r.count == 33 && r.first == 0x00 { r = r.dropFirst() }
    if s.count == 33 && s.first == 0x00 { s = s.dropFirst() }

    // Left-pad to 32 bytes
    let rPadded = Data(repeating: 0, count: max(0, 32 - r.count)) + r
    let sPadded = Data(repeating: 0, count: max(0, 32 - s.count)) + s

    return rPadded + sPadded
}

private func keychainStore(service: String, account: String, value: String) -> Bool {
    let data = Data(value.utf8)
    let deleteQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
    SecItemDelete(deleteQuery as CFDictionary)

    let addQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
    ]
    let status = SecItemAdd(addQuery as CFDictionary, nil)
    if status != errSecSuccess {
        AuthLogger.shared.error("synheart_native_secure_store failed: \(status)")
        return false
    }
    return true
}

private func keychainLoad(service: String, account: String) -> String? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
        return nil
    }
    guard status == errSecSuccess, let data = result as? Data else {
        AuthLogger.shared.error("synheart_native_secure_load failed: \(status)")
        return nil
    }
    return String(data: data, encoding: .utf8)
}

private func keychainDelete(service: String, account: String) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
    let status = SecItemDelete(query as CFDictionary)
    if status == errSecSuccess || status == errSecItemNotFound {
        return true
    }
    AuthLogger.shared.error("synheart_native_secure_delete failed: \(status)")
    return false
}
