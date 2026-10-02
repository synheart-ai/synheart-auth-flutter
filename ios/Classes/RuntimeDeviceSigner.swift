import CryptoKit
import Foundation
import SynheartAuth

/// Signs requests with the device identity synheart-core-runtime registered.
///
/// Registration does not happen in this plugin: the runtime drives it through
/// the `synheart_native_*` callbacks in the `SynheartAuth` pod, and persists the
/// identity in two halves, both through those callbacks:
///
/// - the device record, via `secure_store("synheart-core",
///   "device_record:<app_id>", <JSON>)` (SDK-CONTRACT-CHANGES §4.3 in
///   synheart-core-runtime; unchanged since runtime v0.20.0), and
/// - the Secure Enclave key, under Keychain service `ai.synheart.auth.fficrypto`
///   keyed by `device_id`.
///
/// This type reads and signs through the same public callbacks, so it uses the
/// runtime's key, never a second one. An identity is usable only when both
/// halves exist — the runtime's `has_usable_identity` rule.
///
/// The signed message and header values are the runtime's Mode A ingest
/// signing (`build_ingest_signing_message` + DER + standard base64).
enum RuntimeDeviceSigner {
    static let runtimeService = "synheart-core"
    static let signatureVersion = "1"

    struct SigningFailed: Error {}

    static func deviceRecordKey(appId: String) -> String { "device_record:\(appId)" }

    /// `device_id` from a runtime device record, or nil when absent,
    /// unparseable or blank.
    static func parseDeviceId(_ recordJson: String?) -> String? {
        guard let recordJson, let data = recordJson.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let raw = obj["device_id"] as? String else { return nil }
        let id = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return id.isEmpty ? nil : id
    }

    /// `METHOD\npath\ntimestamp\n` followed by the raw body bytes.
    static func buildMessage(method: String, path: String, timestamp: Int64, bodyBytes: Data?) -> Data {
        var m = Data("\(method.uppercased())\n\(path)\n\(timestamp)\n".utf8)
        if let bodyBytes { m.append(bodyBytes) }
        return m
    }

    /// The runtime-registered `device_id` for `appId`, or nil when this install
    /// holds no usable runtime identity for it.
    static func deviceId(appId: String) -> String? {
        guard let ptr = synheart_native_secure_load(runtimeService, deviceRecordKey(appId: appId)) else {
            return nil
        }
        let json = String(cString: ptr)
        free(ptr)
        guard let id = parseDeviceId(json) else { return nil }
        return synheart_native_key_exists(id) == 1 ? id : nil
    }

    /// The six signed-header values, keyed as the method channel returns them,
    /// or nil when there is no usable runtime identity (the caller then falls
    /// back to the native SDK path). Throws `SigningFailed` when the identity
    /// exists but the Secure Enclave refused to sign.
    static func sign(
        appId: String,
        method: String,
        path: String,
        bodyBytes: Data?,
        epochSeconds: Int64
    ) throws -> [String: String]? {
        guard let deviceId = deviceId(appId: appId) else { return nil }
        let message = buildMessage(method: method, path: path, timestamp: epochSeconds, bodyBytes: bodyBytes)
        let compactB64url: String? = message.withUnsafeBytes { buf in
            guard let base = buf.bindMemory(to: UInt8.self).baseAddress,
                  let out = synheart_native_sign_bytes(deviceId, base, buf.count) else { return nil }
            defer { free(out) }
            return String(cString: out)
        }
        guard let compactB64url, let compact = base64UrlDecode(compactB64url),
              let sig = try? P256.Signing.ECDSASignature(rawRepresentation: compact) else {
            throw SigningFailed()
        }
        return [
            "appId": appId,
            "deviceId": deviceId,
            "signature": sig.derRepresentation.base64EncodedString(),
            "timestamp": String(epochSeconds),
            "nonce": UUID().uuidString.lowercased(),
            "signatureVersion": signatureVersion,
        ]
    }

    private static func base64UrlDecode(_ s: String) -> Data? {
        var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let rem = b64.count % 4
        if rem > 0 { b64 += String(repeating: "=", count: 4 - rem) }
        return Data(base64Encoded: b64)
    }
}

/// Server clock offset applied to runtime-identity signatures. Mirrors the
/// native SDK's `ClockSkewTracker` (offset = server − local, in seconds).
final class ClockOffset: @unchecked Sendable {
    private var offsetSeconds: TimeInterval = 0
    private let lock = NSLock()

    func update(serverTimestamp: TimeInterval) {
        lock.lock(); defer { lock.unlock() }
        offsetSeconds = serverTimestamp - Date().timeIntervalSince1970
    }

    func correctedEpochSeconds() -> Int64 {
        lock.lock(); let offset = offsetSeconds; lock.unlock()
        return Int64(Date().timeIntervalSince1970 + offset)
    }
}
