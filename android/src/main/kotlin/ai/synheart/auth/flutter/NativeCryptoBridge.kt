package ai.synheart.auth.flutter

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
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

/// JNI-callable static bridge for native crypto callbacks.
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
    private const val SECURE_PREFS_FILE = "synheart_core_secure_storage"


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

    private fun storageKey(service: String, key: String): String = "$service::$key"

    private fun securePrefs(): SharedPreferences? {
        val ctx = appContext ?: return null
        return try {
            val masterKey = MasterKey.Builder(ctx)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            EncryptedSharedPreferences.create(
                ctx,
                SECURE_PREFS_FILE,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            Log.e(TAG, "securePrefs init failed: ${e.message}", e)
            null
        }
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

    /// Sign callback input bytes with the device key.
    ///
    /// The native runtime decides which byte sequence to sign (pre-hash or
    /// canonical message). Android Keystore applies SHA-256 internally via SHA256withECDSA.
    /// The callback contract requires base64url of raw 64-byte R||S (not DER).
    @JvmStatic
    fun signBytes(deviceId: String, data: ByteArray): String? {
        return try {
            val keyAlias = alias(deviceId)
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER)
            ks.load(null)
            val entry = ks.getEntry(keyAlias, null) as? KeyStore.PrivateKeyEntry
                ?: throw IllegalStateException("Key not found: $keyAlias")

            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initSign(entry.privateKey)
            sig.update(data)
            val derSignature = sig.sign()
            val rawSignature = derEcdsaToRawRS(derSignature)
                ?: throw IllegalStateException(
                    "DER->R||S conversion failed (derLen=${derSignature.size})",
                )
            val b64 = base64urlEncode(rawSignature)
            Log.i(
                TAG,
                "signBytes($deviceId): ${b64.length} chars (rawLen=${rawSignature.size}, dataLen=${data.size})",
            )
            b64
        } catch (e: Exception) {
            Log.e(TAG, "signBytes($deviceId) failed: ${e.message}", e)
            null
        }
    }

    // ── 3. getAttestation ───────────────────────────────────────────────

    /// Get a Play Integrity attestation token bound to the challenge hash.
    ///
    /// This method BLOCKS the calling thread (which is always a native
    /// runtime background thread, never the Android main thread) using
    /// CountDownLatch until the async Play Integrity Task completes.
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

    // ── 6. secureStore (SMK storage callback) ──────────────────────────

    /// Store secure value for `(service, key)`. Returns 0 on success.
    @JvmStatic
    fun secureStore(service: String, key: String, value: String): Int {
        val prefs = securePrefs() ?: return 1
        return try {
            val ok = prefs.edit().putString(storageKey(service, key), value).commit()
            if (ok) 0 else 1
        } catch (e: Exception) {
            Log.e(TAG, "secureStore($service, $key) failed: ${e.message}", e)
            1
        }
    }

    // ── 7. secureLoad (SMK storage callback) ───────────────────────────

    /// Load secure value for `(service, key)`. Returns null if missing/error.
    @JvmStatic
    fun secureLoad(service: String, key: String): String? {
        val prefs = securePrefs() ?: return null
        return try {
            prefs.getString(storageKey(service, key), null)
        } catch (e: Exception) {
            Log.e(TAG, "secureLoad($service, $key) failed: ${e.message}", e)
            null
        }
    }

    // ── 8. secureDelete (SMK storage callback) ─────────────────────────

    /// Delete secure value for `(service, key)`. Returns 0 on success.
    @JvmStatic
    fun secureDelete(service: String, key: String): Int {
        val prefs = securePrefs() ?: return 1
        return try {
            val ok = prefs.edit().remove(storageKey(service, key)).commit()
            if (ok) 0 else 1
        } catch (e: Exception) {
            Log.e(TAG, "secureDelete($service, $key) failed: ${e.message}", e)
            1
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    /// Convert BigInteger byte array to exactly 32 bytes (left-padded, leading
    /// zero stripped). BigInteger.toByteArray() may return 33 bytes if the
    /// high bit is set (sign byte), or fewer than 32 if leading zeros.
    ///
    /// `internal` so JVM unit tests can exercise P-256 coordinate edge cases
    /// without going through Android Keystore.
    internal fun toUnsigned32(bytes: ByteArray): ByteArray {
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

    /// Convert ASN.1 DER ECDSA signature to raw 64-byte R||S for P-256.
    ///
    /// `internal` so JVM unit tests can round-trip real JDK-generated
    /// signatures through the parser without Android Keystore. The native
    /// runtime's FFI contract requires the compact r||s form, not DER;
    /// any regression here breaks registration silently, so we want
    /// regression coverage.
    internal fun derEcdsaToRawRS(der: ByteArray): ByteArray? {
        var offset = 0
        if (der.isEmpty() || der[offset] != 0x30.toByte()) return null
        offset += 1

        val seqLenParsed = readDerLength(der, offset) ?: return null
        val seqLen = seqLenParsed.first
        offset = seqLenParsed.second
        if (offset + seqLen != der.size) return null

        val rParsed = readDerInteger(der, offset) ?: return null
        val r = normalizeScalar32(rParsed.first) ?: return null
        offset = rParsed.second

        val sParsed = readDerInteger(der, offset) ?: return null
        val s = normalizeScalar32(sParsed.first) ?: return null
        offset = sParsed.second
        if (offset != der.size) return null

        return r + s
    }

    private fun readDerInteger(input: ByteArray, start: Int): Pair<ByteArray, Int>? {
        var offset = start
        if (offset >= input.size || input[offset] != 0x02.toByte()) return null
        offset += 1
        val parsed = readDerLength(input, offset) ?: return null
        val len = parsed.first
        offset = parsed.second
        if (len < 0 || offset + len > input.size) return null
        val value = input.copyOfRange(offset, offset + len)
        return Pair(value, offset + len)
    }

    private fun readDerLength(input: ByteArray, start: Int): Pair<Int, Int>? {
        if (start >= input.size) return null
        val first = input[start].toInt() and 0xFF
        if (first and 0x80 == 0) {
            return Pair(first, start + 1)
        }
        val count = first and 0x7F
        if (count == 0 || count > 4 || start + 1 + count > input.size) return null
        var len = 0
        for (i in 0 until count) {
            len = (len shl 8) or (input[start + 1 + i].toInt() and 0xFF)
        }
        return Pair(len, start + 1 + count)
    }

    private fun normalizeScalar32(value: ByteArray): ByteArray? {
        var idx = 0
        while (idx < value.size && value[idx] == 0.toByte()) idx++
        val trimmed = value.copyOfRange(idx, value.size)
        if (trimmed.size > 32) return null
        return ByteArray(32 - trimmed.size) + trimmed
    }

}
