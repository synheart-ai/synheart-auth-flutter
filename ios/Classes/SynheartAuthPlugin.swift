import Flutter
import UIKit
import SynheartAuth

/// Flutter plugin that bridges Dart calls to the native SynheartAuth iOS SDK.
///
/// In production, this imports and delegates to the `SynheartAuth` framework.
/// The native SDK handles all Secure Enclave crypto, Keychain storage, and networking.
public class SynheartAuthPlugin: NSObject, FlutterPlugin {

    private let clockOffset = ClockOffset()

    /// Keychain reads can retry for ~1.5 s and Secure Enclave signing blocks,
    /// so runtime-identity work stays off the platform thread.
    private let workQueue = DispatchQueue(label: "ai.synheart.auth.flutter.signing", qos: .userInitiated)

    private func runOffMain(_ result: @escaping FlutterResult, _ work: @escaping () -> Any?) {
        workQueue.async {
            let value = work()
            DispatchQueue.main.async { result(value) }
        }
    }

    public static func register(with registrar: FlutterPluginRegistrar) {
        // Keep synheart_native_* @_cdecl symbols alive so the static linker
        // does not strip them before DynamicLibrary.process() can resolve them.
        _ = SynheartNativeCryptoAnchor.all

        let channel = FlutterMethodChannel(
            name: "ai.synheart.auth",
            binaryMessenger: registrar.messenger()
        )
        let instance = SynheartAuthPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        let args = call.arguments as? [String: Any] ?? [:]

        switch call.method {
        case "configure":
            guard let baseUrl = args["baseUrl"] as? String else {
                result(FlutterError(code: "INVALID_ARGS", message: "Missing baseUrl", details: nil))
                return
            }
            SynheartAuth.shared.configure(baseUrl: baseUrl)
            result(nil)

        case "isRegistered":
            guard let appId = args["appId"] as? String else {
                result(FlutterError(code: "INVALID_ARGS", message: "Missing appId", details: nil))
                return
            }
            // isRegistered / getDeviceId / signRequest read the runtime's
            // identity first, then fall back to the native SDK's own store —
            // the only store 0.1.11 and earlier read.
            runOffMain(result) {
                RuntimeDeviceSigner.deviceId(appId: appId) != nil
                    || SynheartAuth.shared.isRegistered(appId: appId)
            }

        case "registerDevice":
            guard let appId = args["appId"] as? String else {
                result(FlutterError(code: "INVALID_ARGS", message: "Missing appId", details: nil))
                return
            }
            Task {
                do {
                    let reg = try await SynheartAuth.shared.registerDevice(appId: appId)
                    result([
                        "status": reg.status.rawValue,
                        "deviceId": reg.deviceId as Any,
                    ])
                } catch let error as SynheartAuthError {
                    result(self.flutterError(from: error))
                } catch {
                    result(FlutterError(code: "UNKNOWN", message: error.localizedDescription, details: nil))
                }
            }

        case "signRequest":
            guard let appId = args["appId"] as? String,
                  let method = args["method"] as? String,
                  let path = args["path"] as? String else {
                result(FlutterError(code: "INVALID_ARGS", message: "Missing required args", details: nil))
                return
            }
            let bodyBytes = (args["bodyBytes"] as? FlutterStandardTypedData)?.data
            let epochSeconds = clockOffset.correctedEpochSeconds()
            runOffMain(result) {
                do {
                    if let signed = try RuntimeDeviceSigner.sign(
                        appId: appId,
                        method: method,
                        path: path,
                        bodyBytes: bodyBytes,
                        epochSeconds: epochSeconds
                    ) {
                        return signed
                    }
                    return try self.nativeSdkSign(appId: appId, method: method, path: path, bodyBytes: bodyBytes)
                } catch is RuntimeDeviceSigner.SigningFailed {
                    return FlutterError(
                        code: "CRYPTO_ERROR",
                        message: "Signing with the runtime device key failed",
                        details: nil
                    )
                } catch let error as SynheartAuthError {
                    return self.flutterError(from: error)
                } catch {
                    return FlutterError(code: "UNKNOWN", message: error.localizedDescription, details: nil)
                }
            }

        case "getDeviceId":
            guard let appId = args["appId"] as? String else {
                result(FlutterError(code: "INVALID_ARGS", message: "Missing appId", details: nil))
                return
            }
            runOffMain(result) {
                RuntimeDeviceSigner.deviceId(appId: appId)
                    ?? SynheartAuth.shared.getDeviceId(appId: appId)
            }

        case "rotateKey":
            guard let appId = args["appId"] as? String else {
                result(FlutterError(code: "INVALID_ARGS", message: "Missing appId", details: nil))
                return
            }
            Task {
                do {
                    let rot = try await SynheartAuth.shared.rotateKey(appId: appId)
                    result(["status": rot.status.rawValue])
                } catch let error as SynheartAuthError {
                    result(self.flutterError(from: error))
                } catch {
                    result(FlutterError(code: "UNKNOWN", message: error.localizedDescription, details: nil))
                }
            }

        case "resetDeviceIdentity":
            guard let appId = args["appId"] as? String else {
                result(FlutterError(code: "INVALID_ARGS", message: "Missing appId", details: nil))
                return
            }
            SynheartAuth.shared.resetDeviceIdentity(appId: appId)
            result(nil)

        case "correctClockSkew":
            guard let serverTimestamp = args["serverTimestamp"] as? Double else {
                result(FlutterError(code: "INVALID_ARGS", message: "Missing serverTimestamp", details: nil))
                return
            }
            clockOffset.update(serverTimestamp: serverTimestamp)
            SynheartAuth.shared.correctClockSkew(serverTimestamp: serverTimestamp)
            result(nil)

        default:
            result(FlutterMethodNotImplemented)
        }
    }

    /// The 0.1.11-and-earlier path: the native SDK's own appId-scoped store. Nothing in
    /// a host app registers into it (registration runs in the runtime), so in
    /// practice this throws `notRegistered`; kept as the fallback so a device
    /// without a runtime identity behaves exactly as before.
    private func nativeSdkSign(appId: String, method: String, path: String, bodyBytes: Data?) throws -> [String: String] {
        let headers = try SynheartAuth.shared.signRequest(
            appId: appId,
            method: method,
            path: path,
            bodyBytes: bodyBytes
        )
        return [
            "appId": headers.appId,
            "deviceId": headers.deviceId,
            "signature": headers.signature,
            "timestamp": headers.timestamp,
            "nonce": headers.nonce,
            "signatureVersion": headers.signatureVersion,
        ]
    }

    private func flutterError(from error: SynheartAuthError) -> FlutterError {
        let (code, message) = switch error {
        case .networkError(let msg): ("NETWORK_ERROR", msg)
        case .challengeExpired: ("CHALLENGE_EXPIRED", "Challenge expired")
        case .attestationUnavailable: ("ATTESTATION_UNAVAILABLE", "Attestation unavailable")
        case .keyInvalidated: ("KEY_INVALIDATED", "Key invalidated")
        case .clockSkew: ("CLOCK_SKEW", "Clock skew detected")
        case .alreadyRegistered: ("ALREADY_REGISTERED", "Already registered")
        case .notRegistered: ("NOT_REGISTERED", "Not registered")
        case .notConfigured: ("NOT_CONFIGURED", "Not configured")
        case .registrationInProgress: ("REGISTRATION_IN_PROGRESS", "Registration in progress")
        case .serverError(let code, let msg): (code, msg)
        case .keychainError(let status): ("KEYCHAIN_ERROR", "Keychain error: \(status)")
        case .cryptoError(let msg): ("CRYPTO_ERROR", msg)
        case .invalidStateTransition(let from, let to): ("INVALID_STATE_TRANSITION", "\(from) → \(to)")
        }
        return FlutterError(code: code, message: message, details: nil)
    }
}
