package ai.synheart.auth.flutter

import org.json.JSONObject
import java.util.UUID

/// Signs requests with the device identity synheart-core-runtime registered.
///
/// Registration does not happen in this plugin: the runtime drives it through
/// the [NativeCryptoBridge] callbacks, and it persists the identity in two
/// halves, both written through those callbacks:
///
/// - the device record, via `secure_store("synheart-core",
///   "device_record:<app_id>", <JSON>)` (SDK-CONTRACT-CHANGES §4.3 in
///   synheart-core-runtime; unchanged since runtime v0.20.0), and
/// - the P-256 key, in Android Keystore under `synheart_device_<device_id>`.
///
/// An identity is usable only when both halves exist — the same rule as the
/// runtime's `has_usable_identity`. The record without the key cannot sign;
/// the key without the record has no `device_id` to claim.
///
/// The signed message and header values are byte-for-byte the runtime's Mode A
/// ingest signing (`build_ingest_signing_message` + DER + standard base64), so
/// the server sees no difference between a runtime-signed and a plugin-signed
/// request.
///
/// Everything platform-specific is injected, so this class runs in JVM tests.
internal class RuntimeDeviceSigner(
    private val secureLoad: (service: String, key: String) -> String?,
    private val keyExists: (deviceId: String) -> Boolean,
    private val signDer: (deviceId: String, message: ByteArray) -> ByteArray?,
    private val epochSeconds: () -> Long,
    private val base64: (ByteArray) -> String,
    private val newNonce: () -> String = { UUID.randomUUID().toString() },
) {
    /// The runtime key exists but signing with it failed.
    class SigningFailed(message: String) : Exception(message)

    companion object {
        const val RUNTIME_SERVICE = "synheart-core"
        const val SIGNATURE_VERSION = "1"

        fun deviceRecordKey(appId: String): String = "device_record:$appId"

        /// `device_id` from a runtime device record, or null when the record is
        /// absent, unparseable or carries a blank id.
        fun parseDeviceId(recordJson: String?): String? {
            if (recordJson.isNullOrBlank()) return null
            return try {
                JSONObject(recordJson).optString("device_id", "").trim().ifEmpty { null }
            } catch (_: Exception) {
                null
            }
        }

        /// `METHOD\npath\ntimestamp\n` followed by the raw body bytes — the
        /// runtime's `build_ingest_signing_message`.
        fun buildMessage(
            method: String,
            path: String,
            timestampSeconds: Long,
            bodyBytes: ByteArray?,
        ): ByteArray {
            val header = "${method.uppercase()}\n$path\n$timestampSeconds\n"
                .toByteArray(Charsets.UTF_8)
            return if (bodyBytes == null) header else header + bodyBytes
        }
    }

    /// The runtime-registered `device_id` for [appId], or null when this
    /// install holds no usable runtime identity for it.
    fun deviceId(appId: String): String? {
        val id = parseDeviceId(secureLoad(RUNTIME_SERVICE, deviceRecordKey(appId)))
            ?: return null
        return if (keyExists(id)) id else null
    }

    /// The six signed-header values, keyed as the method channel returns them,
    /// or null when there is no usable runtime identity for [appId] (the caller
    /// then falls back to the native SDK path).
    ///
    /// @throws SigningFailed when the identity exists but the Keystore refused
    ///   to sign.
    fun sign(
        appId: String,
        method: String,
        path: String,
        bodyBytes: ByteArray?,
    ): Map<String, String>? {
        val deviceId = deviceId(appId) ?: return null
        val timestamp = epochSeconds()
        val message = buildMessage(method, path, timestamp, bodyBytes)
        val der = signDer(deviceId, message)
            ?: throw SigningFailed("Signing with the runtime device key failed")
        return mapOf(
            "appId" to appId,
            "deviceId" to deviceId,
            "signature" to base64(der),
            "timestamp" to timestamp.toString(),
            "nonce" to newNonce(),
            "signatureVersion" to SIGNATURE_VERSION,
        )
    }
}

/// Server clock offset applied to runtime-identity signatures. Mirrors the
/// native SDK's `ClockSkewTracker` (offset = server − local, in seconds).
internal class ClockOffset(private val nowMillis: () -> Long = System::currentTimeMillis) {
    @Volatile
    private var offsetSeconds: Double = 0.0

    fun update(serverTimestampSeconds: Double) {
        offsetSeconds = serverTimestampSeconds - nowMillis() / 1000.0
    }

    fun correctedEpochSeconds(): Long = (nowMillis() / 1000.0 + offsetSeconds).toLong()
}
