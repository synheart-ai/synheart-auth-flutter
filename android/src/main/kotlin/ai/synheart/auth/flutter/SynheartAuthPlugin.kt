package ai.synheart.auth.flutter

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import kotlinx.coroutines.*
import android.content.pm.ApplicationInfo
import android.util.Log

/// Flutter plugin that bridges Dart calls to the native SynheartAuth Android SDK.
///
/// In production, this imports and delegates to `ai.synheart.auth.SynheartAuth`.
/// The native SDK handles all Android Keystore crypto, storage, and networking.
class SynheartAuthPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var applicationContext: android.content.Context? = null

    private val clockOffset = ClockOffset()

    /// Signs with the identity synheart-core-runtime registered — the only
    /// identity a host app can have, since registration runs in the runtime.
    /// See [RuntimeDeviceSigner].
    private val runtimeSigner = RuntimeDeviceSigner(
        secureLoad = NativeCryptoBridge::secureLoad,
        keyExists = NativeCryptoBridge::keyExists,
        signDer = NativeCryptoBridge::signDer,
        epochSeconds = clockOffset::correctedEpochSeconds,
        base64 = { android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP) },
    )

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, "ai.synheart.auth")
        channel.setMethodCallHandler(this)
        applicationContext = binding.applicationContext

        // Initialize the native crypto bridge with app context (for Play Integrity).
        NativeCryptoBridge.init(binding.applicationContext)

        // Load the native JNI library that exports C symbols for the native runtime.
        try {
            System.loadLibrary("synheart_native_crypto")
        } catch (e: UnsatisfiedLinkError) {
            Log.e("SynheartAuthPlugin", "Failed to load libsynheart_native_crypto.so", e)
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        scope.cancel()
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "configure" -> {
                val baseUrl = call.argument<String>("baseUrl")
                    ?: return result.error("INVALID_ARGS", "Missing baseUrl", null)
                val attestation = applicationContext?.let { PlayIntegrityAttestationProvider(it) }
                val debuggable =
                    applicationContext?.applicationInfo?.flags?.and(ApplicationInfo.FLAG_DEBUGGABLE) != 0
                setLoggingEnabledIfSupported(debuggable)
                ai.synheart.auth.SynheartAuth.shared.configure(baseUrl, attestation)
                result.success(null)
            }

            // isRegistered / getDeviceId / signRequest read the runtime's
            // identity first (secure-storage reads can retry for ~1 s and
            // Keystore signing is an IPC, so off the main thread), then fall
            // back to the native SDK's own store, which is what 0.1.11 and
            // earlier read exclusively.
            "isRegistered" -> {
                val appId = call.argument<String>("appId")
                    ?: return result.error("INVALID_ARGS", "Missing appId", null)
                scope.launch {
                    val registered = withContext(Dispatchers.IO) {
                        runtimeSigner.deviceId(appId) != null ||
                            ai.synheart.auth.SynheartAuth.shared.isRegistered(appId)
                    }
                    result.success(registered)
                }
            }

            "registerDevice" -> {
                val appId = call.argument<String>("appId")
                    ?: return result.error("INVALID_ARGS", "Missing appId", null)
                scope.launch {
                    try {
                        val reg = ai.synheart.auth.SynheartAuth.shared.registerDevice(appId)
                        result.success(
                            mapOf(
                                "status" to reg.status.name.lowercase(),
                                "deviceId" to reg.deviceId
                            )
                        )
                    } catch (e: ai.synheart.auth.models.SynheartAuthError) {
                        Log.e("SynheartAuthPlugin", "registerDevice failed: ${e.message}")
                        result.error(errorCode(e), e.message, null)
                    } catch (e: Exception) {
                        Log.e("SynheartAuthPlugin", "registerDevice unexpected error", e)
                        result.error("UNKNOWN", e.message, null)
                    }
                }
            }

            "signRequest" -> {
                val appId = call.argument<String>("appId")
                    ?: return result.error("INVALID_ARGS", "Missing appId", null)
                val method = call.argument<String>("method")
                    ?: return result.error("INVALID_ARGS", "Missing method", null)
                val path = call.argument<String>("path")
                    ?: return result.error("INVALID_ARGS", "Missing path", null)
                val bodyBytes = call.argument<ByteArray>("bodyBytes")

                scope.launch {
                    try {
                        val signed = withContext(Dispatchers.IO) {
                            runtimeSigner.sign(appId, method, path, bodyBytes)
                                ?: nativeSdkSign(appId, method, path, bodyBytes)
                        }
                        result.success(signed)
                    } catch (e: RuntimeDeviceSigner.SigningFailed) {
                        result.error("CRYPTO_ERROR", e.message, null)
                    } catch (e: ai.synheart.auth.models.SynheartAuthError) {
                        result.error(errorCode(e), e.message, null)
                    } catch (e: Exception) {
                        result.error("UNKNOWN", e.message, null)
                    }
                }
            }

            "getDeviceId" -> {
                val appId = call.argument<String>("appId")
                    ?: return result.error("INVALID_ARGS", "Missing appId", null)
                scope.launch {
                    val deviceId = withContext(Dispatchers.IO) {
                        runtimeSigner.deviceId(appId)
                            ?: ai.synheart.auth.SynheartAuth.shared.getDeviceId(appId)
                    }
                    result.success(deviceId)
                }
            }

            "rotateKey" -> {
                val appId = call.argument<String>("appId")
                    ?: return result.error("INVALID_ARGS", "Missing appId", null)
                scope.launch {
                    try {
                        val rot = ai.synheart.auth.SynheartAuth.shared.rotateKey(appId)
                        result.success(mapOf("status" to rot.status.name.lowercase()))
                    } catch (e: ai.synheart.auth.models.SynheartAuthError) {
                        result.error(errorCode(e), e.message, null)
                    } catch (e: Exception) {
                        result.error("UNKNOWN", e.message, null)
                    }
                }
            }

            "resetDeviceIdentity" -> {
                val appId = call.argument<String>("appId")
                    ?: return result.error("INVALID_ARGS", "Missing appId", null)
                ai.synheart.auth.SynheartAuth.shared.resetDeviceIdentity(appId)
                result.success(null)
            }

            "correctClockSkew" -> {
                val serverTimestamp = call.argument<Double>("serverTimestamp")
                    ?: return result.error("INVALID_ARGS", "Missing serverTimestamp", null)
                clockOffset.update(serverTimestamp)
                ai.synheart.auth.SynheartAuth.shared.correctClockSkew(serverTimestamp)
                result.success(null)
            }

            else -> result.notImplemented()
        }
    }

    /// The 0.1.11-and-earlier path: the native SDK's own app_id-scoped store. Nothing
    /// in a host app can register into it (registration runs in the runtime),
    /// so in practice this raises NotRegistered; kept as the fallback so a
    /// device without a runtime identity behaves exactly as before.
    private fun nativeSdkSign(
        appId: String,
        method: String,
        path: String,
        bodyBytes: ByteArray?,
    ): Map<String, String> {
        val headers = ai.synheart.auth.SynheartAuth.shared.signRequest(
            appId, method, path, bodyBytes
        )
        return mapOf(
            "appId" to headers.appId,
            "deviceId" to headers.deviceId,
            "signature" to headers.signature,
            "timestamp" to headers.timestamp,
            "nonce" to headers.nonce,
            "signatureVersion" to headers.signatureVersion
        )
    }

    private fun setLoggingEnabledIfSupported(enabled: Boolean) {
        try {
            val auth = ai.synheart.auth.SynheartAuth.shared
            val method = auth::class.java.getMethod(
                "setLoggingEnabled",
                Boolean::class.javaPrimitiveType
            )
            method.invoke(auth, enabled)
        } catch (_: NoSuchMethodException) {
            // Compatible with newer SDK versions where logging API was removed.
        } catch (_: Throwable) {
            // Logging should never block SDK configuration.
        }
    }

    private fun errorCode(e: ai.synheart.auth.models.SynheartAuthError): String = when (e) {
        is ai.synheart.auth.models.SynheartAuthError.NetworkError -> "NETWORK_ERROR"
        is ai.synheart.auth.models.SynheartAuthError.ChallengeExpired -> "CHALLENGE_EXPIRED"
        is ai.synheart.auth.models.SynheartAuthError.KeyInvalidated -> "KEY_INVALIDATED"
        is ai.synheart.auth.models.SynheartAuthError.ClockSkew -> "CLOCK_SKEW"
        is ai.synheart.auth.models.SynheartAuthError.AlreadyRegistered -> "ALREADY_REGISTERED"
        is ai.synheart.auth.models.SynheartAuthError.NotRegistered -> "NOT_REGISTERED"
        is ai.synheart.auth.models.SynheartAuthError.NotConfigured -> "NOT_CONFIGURED"
        is ai.synheart.auth.models.SynheartAuthError.RegistrationInProgress -> "REGISTRATION_IN_PROGRESS"
        is ai.synheart.auth.models.SynheartAuthError.ServerError -> e.code
        is ai.synheart.auth.models.SynheartAuthError.CryptoError -> "CRYPTO_ERROR"
        is ai.synheart.auth.models.SynheartAuthError.StorageError -> "STORAGE_ERROR"
        is ai.synheart.auth.models.SynheartAuthError.InvalidStateTransition -> "INVALID_STATE_TRANSITION"
    }
}
