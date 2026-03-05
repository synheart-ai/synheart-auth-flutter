package com.synheart.auth.flutter

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import kotlinx.coroutines.*

/// Flutter plugin that bridges Dart calls to the native SynheartAuth Android SDK.
///
/// In production, this imports and delegates to `com.synheart.auth.SynheartAuth`.
/// The native SDK handles all Android Keystore crypto, storage, and networking.
class SynheartAuthPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, "com.synheart.auth")
        channel.setMethodCallHandler(this)
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
                com.synheart.auth.SynheartAuth.shared.configure(baseUrl)
                result.success(null)
            }

            "isRegistered" -> {
                val appId = call.argument<String>("appId")
                    ?: return result.error("INVALID_ARGS", "Missing appId", null)
                result.success(com.synheart.auth.SynheartAuth.shared.isRegistered(appId))
            }

            "registerDevice" -> {
                val appId = call.argument<String>("appId")
                    ?: return result.error("INVALID_ARGS", "Missing appId", null)
                scope.launch {
                    try {
                        val reg = com.synheart.auth.SynheartAuth.shared.registerDevice(appId)
                        result.success(
                            mapOf(
                                "status" to reg.status.name.lowercase(),
                                "deviceId" to reg.deviceId
                            )
                        )
                    } catch (e: com.synheart.auth.models.SynheartAuthError) {
                        result.error(errorCode(e), e.message, null)
                    } catch (e: Exception) {
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

                try {
                    val headers = com.synheart.auth.SynheartAuth.shared.signRequest(
                        appId, method, path, bodyBytes
                    )
                    result.success(
                        mapOf(
                            "appId" to headers.appId,
                            "deviceId" to headers.deviceId,
                            "signature" to headers.signature,
                            "timestamp" to headers.timestamp,
                            "nonce" to headers.nonce,
                            "signatureVersion" to headers.signatureVersion
                        )
                    )
                } catch (e: com.synheart.auth.models.SynheartAuthError) {
                    result.error(errorCode(e), e.message, null)
                } catch (e: Exception) {
                    result.error("UNKNOWN", e.message, null)
                }
            }

            "getDeviceId" -> {
                val appId = call.argument<String>("appId")
                    ?: return result.error("INVALID_ARGS", "Missing appId", null)
                result.success(com.synheart.auth.SynheartAuth.shared.getDeviceId(appId))
            }

            "rotateKey" -> {
                val appId = call.argument<String>("appId")
                    ?: return result.error("INVALID_ARGS", "Missing appId", null)
                scope.launch {
                    try {
                        val rot = com.synheart.auth.SynheartAuth.shared.rotateKey(appId)
                        result.success(mapOf("status" to rot.status.name.lowercase()))
                    } catch (e: com.synheart.auth.models.SynheartAuthError) {
                        result.error(errorCode(e), e.message, null)
                    } catch (e: Exception) {
                        result.error("UNKNOWN", e.message, null)
                    }
                }
            }

            "resetDeviceIdentity" -> {
                val appId = call.argument<String>("appId")
                    ?: return result.error("INVALID_ARGS", "Missing appId", null)
                com.synheart.auth.SynheartAuth.shared.resetDeviceIdentity(appId)
                result.success(null)
            }

            "correctClockSkew" -> {
                val serverTimestamp = call.argument<Double>("serverTimestamp")
                    ?: return result.error("INVALID_ARGS", "Missing serverTimestamp", null)
                com.synheart.auth.SynheartAuth.shared.correctClockSkew(serverTimestamp)
                result.success(null)
            }

            else -> result.notImplemented()
        }
    }

    private fun errorCode(e: com.synheart.auth.models.SynheartAuthError): String = when (e) {
        is com.synheart.auth.models.SynheartAuthError.NetworkError -> "NETWORK_ERROR"
        is com.synheart.auth.models.SynheartAuthError.ChallengeExpired -> "CHALLENGE_EXPIRED"
        is com.synheart.auth.models.SynheartAuthError.KeyInvalidated -> "KEY_INVALIDATED"
        is com.synheart.auth.models.SynheartAuthError.ClockSkew -> "CLOCK_SKEW"
        is com.synheart.auth.models.SynheartAuthError.AlreadyRegistered -> "ALREADY_REGISTERED"
        is com.synheart.auth.models.SynheartAuthError.NotRegistered -> "NOT_REGISTERED"
        is com.synheart.auth.models.SynheartAuthError.NotConfigured -> "NOT_CONFIGURED"
        is com.synheart.auth.models.SynheartAuthError.RegistrationInProgress -> "REGISTRATION_IN_PROGRESS"
        is com.synheart.auth.models.SynheartAuthError.ServerError -> e.code
        is com.synheart.auth.models.SynheartAuthError.CryptoError -> "CRYPTO_ERROR"
        is com.synheart.auth.models.SynheartAuthError.StorageError -> "STORAGE_ERROR"
        is com.synheart.auth.models.SynheartAuthError.InvalidStateTransition -> "INVALID_STATE_TRANSITION"
    }
}
