package ai.synheart.auth.flutter

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/// JNI-callable static bridge for RFC-CORE-0008 crypto callbacks.
///
/// synheart_native_bridge.cpp looks up class "ai/synheart/auth/flutter/NativeCryptoBridge"
/// and calls these @JvmStatic methods. Each method signature must match the JNI
/// descriptors used in the C++ GetStaticMethodID calls.
///
/// Key alias convention: "synheart_device_<deviceId>"
object NativeCryptoBridge {
    private const val TAG = "NativeCryptoBridge"
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS_PREFIX = "synheart_device_"


    /// Application context captured during plugin initialization. Required for
    /// IntegrityManagerFactory.create(context).
    @Volatile
    private var appContext: Context? = null

    /// Must be called from SynheartAuthPlugin.onAttachedToEngine() before any
    /// native callback is invoked.
    fun init(context: Context) {
        appContext = context.applicationContext
        Log.i(TAG, "Context initialized")
    }

    // ── Key alias helper ────────────────────────────────────────────────

    private fun alias(deviceId: String): String = "$KEY_ALIAS_PREFIX$deviceId"

    // ── Base64url helpers (RFC 4648 §5, no padding) ─────────────────────

    private fun base64urlEncode(data: ByteArray): String =
        Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    // ── 1. generateKey ──────────────────────────────────────────────────

    /// Generate a P-256 key pair in Android Keystore.
    /// Returns JSON: {"x":"<base64url>","y":"<base64url>"} or null on failure.
    @JvmStatic
    fun generateKey(deviceId: String): String? {
        return try {
            val keyAlias = alias(deviceId)
            val spec = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
                .build()

            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER
            )
            kpg.initialize(spec)
            val keyPair = kpg.generateKeyPair()

            // Extract uncompressed X9.62 public key (0x04 || x || y).
            // Android exports EC public keys in X.509/SubjectPublicKeyInfo format.
            // We parse the raw key bytes from the encoded form.
            val pubKey = keyPair.public
            val factory = KeyFactory.getInstance("EC")
            val keySpec = factory.getKeySpec(pubKey, java.security.spec.ECPublicKeySpec::class.java)
            val xBytes = toUnsigned32(keySpec.w.affineX.toByteArray())
            val yBytes = toUnsigned32(keySpec.w.affineY.toByteArray())

            val xB64 = base64urlEncode(xBytes)
            val yB64 = base64urlEncode(yBytes)

            val json = """{"x":"$xB64","y":"$yB64"}"""
            Log.i(TAG, "generateKey($deviceId): success")
            json
        } catch (e: Exception) {
            Log.e(TAG, "generateKey($deviceId) failed: ${e.message}", e)
            null
        }
    }

    // ── 2. signBytes ────────────────────────────────────────────────────

    /// Sign raw bytes with the device key. The C++ caller has already
    /// computed the hash if needed — we sign the raw input as-is using
    /// SHA256withECDSA (Android Keystore performs the SHA-256 internally).
    ///
    /// Returns base64url-encoded raw R||S (64 bytes) signature, or null.
    @JvmStatic
    fun signBytes(deviceId: String, data: ByteArray): String? {
        return try {
            val keyAlias = alias(deviceId)
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER)
            ks.load(null)
            val entry = ks.getEntry(keyAlias, null) as? KeyStore.PrivateKeyEntry
                ?: throw IllegalStateException("Key not found: $keyAlias")

            val sig = Signature.getInstance("NONEwithECDSA")
            sig.initSign(entry.privateKey)
            sig.update(data)
            val derSignature = sig.sign()

            // Return DER encoded signature directly as expected by backend
            val b64 = base64urlEncode(derSignature)
            Log.i(TAG, "signBytes($deviceId): ${b64.length} chars (dataLen=${data.size})")
            b64
        } catch (e: Exception) {
            Log.e(TAG, "signBytes($deviceId) failed: ${e.message}", e)
            null
        }
    }

    // ── 3. getAttestation ───────────────────────────────────────────────

    /// Get a Play Integrity attestation token bound to the challenge hash.
    ///
    /// This method BLOCKS the calling thread (which is always a Rust background
    /// thread, never the Android main thread) using CountDownLatch until the
    /// async Play Integrity Task completes.
    ///
    /// Returns JSON: {"format":"play-integrity","blob":"<compact JOSE token>"}
    /// or {"format":"none","blob":""} if Play Integrity is unavailable.
    @JvmStatic
    fun getAttestation(deviceId: String, challengeHash: ByteArray): String? {
        val ctx = appContext
        if (ctx == null) {
            Log.e(TAG, "getAttestation: appContext is null — was init() called?")
            return """{"format":"none","blob":""}"""
        }

        return try {
            // Play Integrity expects the nonce as a base64url-encoded string.
            val nonce = base64urlEncode(challengeHash)
            Log.i(TAG, "getAttestation($deviceId): requesting Play Integrity token (nonce=${nonce.take(16)}...)")

            val integrityManager = IntegrityManagerFactory.create(ctx)
            val request = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .build()

            // Synchronous bridge: block until async Task completes.
            val latch = CountDownLatch(1)
            val tokenRef = AtomicReference<String?>(null)
            val errorRef = AtomicReference<Exception?>(null)

            integrityManager.requestIntegrityToken(request)
                .addOnSuccessListener { response ->
                    tokenRef.set(response.token())
                    latch.countDown()
                }
                .addOnFailureListener { e ->
                    errorRef.set(e)
                    latch.countDown()
                }

            latch.await()

            val error = errorRef.get()
            if (error != null) {
                Log.e(TAG, "getAttestation: Play Integrity failed: ${error.javaClass.simpleName}: ${error.message}", error)
                return """{"format":"none","blob":""}"""
            }

            val token = tokenRef.get()
            if (token.isNullOrEmpty()) {
                Log.e(TAG, "getAttestation: Play Integrity returned empty token")
                return """{"format":"none","blob":""}"""
            }

            Log.i(TAG, "getAttestation($deviceId): Play Integrity token obtained (${token.length} chars)")
            """{"format":"play-integrity","blob":"$token"}"""
        } catch (e: Exception) {
            Log.e(TAG, "getAttestation($deviceId) failed: ${e.javaClass.simpleName}: ${e.message}", e)
            """{"format":"none","blob":""}"""
        }
    }

    // ── 4. keyExists ────────────────────────────────────────────────────

    /// Check if a key exists for the given device ID.
    @JvmStatic
    fun keyExists(deviceId: String): Boolean {
        return try {
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER)
            ks.load(null)
            ks.containsAlias(alias(deviceId))
        } catch (e: Exception) {
            Log.e(TAG, "keyExists($deviceId) failed: ${e.message}", e)
            false
        }
    }

    // ── 5. deleteKey ────────────────────────────────────────────────────

    /// Delete the key for the given device ID. Returns true on success.
    @JvmStatic
    fun deleteKey(deviceId: String): Boolean {
        return try {
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER)
            ks.load(null)
            val keyAlias = alias(deviceId)
            if (ks.containsAlias(keyAlias)) {
                ks.deleteEntry(keyAlias)
                Log.i(TAG, "deleteKey($deviceId): deleted")
            } else {
                Log.i(TAG, "deleteKey($deviceId): key not found (no-op)")
            }
            true
        } catch (e: Exception) {
            Log.e(TAG, "deleteKey($deviceId) failed: ${e.message}", e)
            false
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    /// Convert BigInteger byte array to exactly 32 bytes (left-padded, leading
    /// zero stripped). BigInteger.toByteArray() may return 33 bytes if the
    /// high bit is set (sign byte), or fewer than 32 if leading zeros.
    private fun toUnsigned32(bytes: ByteArray): ByteArray {
        // Strip leading zero byte if present (BigInteger sign byte).
        val stripped = if (bytes.size > 32 && bytes[0] == 0.toByte()) {
            bytes.copyOfRange(1, bytes.size)
        } else {
            bytes
        }
        // Left-pad to 32 bytes if necessary.
        return if (stripped.size < 32) {
            ByteArray(32 - stripped.size) + stripped
        } else {
            stripped.copyOfRange(stripped.size - 32, stripped.size)
        }
    }
}
