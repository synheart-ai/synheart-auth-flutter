package ai.synheart.auth.flutter

import ai.synheart.auth.SynheartAuth
import ai.synheart.auth.models.SynheartAuthError
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.test.assertFailsWith

class RuntimeDeviceSignerTest {

    private val appId = "com.example.app"
    private val deviceId = "dev_0123456789abcdef"

    /// What the runtime writes for `device_record:<app_id>` (DeviceRecord serde).
    private fun recordJson(id: String = deviceId) =
        """{"app_id":"$appId","subject_id":"sub_1","device_id":"$id",""" +
            """"public_jwk":{"kty":"EC","crv":"P-256","x":"a","y":"b"},""" +
            """"registered_at_ms":1700000000000,"attestation":"hardware"}"""

    /// A stand-in for secure storage + Keystore: a map of (service, key) and
    /// one software P-256 key per device id.
    private class FakePlatform {
        val store = mutableMapOf<Pair<String, String>, String>()
        val keys = mutableMapOf<String, KeyPair>()
        val loads = mutableListOf<Pair<String, String>>()
        var failSigning = false

        fun addKey(deviceId: String): KeyPair {
            val gen = KeyPairGenerator.getInstance("EC")
            gen.initialize(ECGenParameterSpec("secp256r1"))
            return gen.generateKeyPair().also { keys[deviceId] = it }
        }

        fun signer(nowSeconds: Long = 1_700_000_000L) = RuntimeDeviceSigner(
            secureLoad = { s, k -> loads += s to k; store[s to k] },
            keyExists = { keys.containsKey(it) },
            signDer = { id, msg ->
                if (failSigning) null
                else keys[id]?.let { kp ->
                    Signature.getInstance("SHA256withECDSA").run {
                        initSign(kp.private); update(msg); sign()
                    }
                }
            },
            epochSeconds = { nowSeconds },
            base64 = { Base64.getEncoder().encodeToString(it) },
            newNonce = { "nonce-1" },
        )
    }

    private fun FakePlatform.writeRecord(json: String = recordJson()) {
        store[RuntimeDeviceSigner.RUNTIME_SERVICE to RuntimeDeviceSigner.deviceRecordKey(appId)] = json
    }

    // ── message ─────────────────────────────────────────────────────────

    @Test
    fun messageMatchesRuntimeIngestSigningLayout() {
        // Same vector as synheart-core-runtime ingest_sign.rs `signing_message_layout`.
        val m = RuntimeDeviceSigner.buildMessage("post", "/v1/hsi", 1_700_000_000L, """{"a":1}""".toByteArray())
        assertEquals("POST\n/v1/hsi\n1700000000\n{\"a\":1}", String(m, Charsets.UTF_8))
    }

    @Test
    fun messageWithoutBodyEndsAtTimestampNewline() {
        val m = RuntimeDeviceSigner.buildMessage("GET", "/v1/x", 5L, null)
        assertArrayEquals("GET\n/v1/x\n5\n".toByteArray(), m)
    }

    // ── device record ───────────────────────────────────────────────────

    @Test
    fun parsesDeviceIdFromRuntimeRecord() {
        assertEquals(deviceId, RuntimeDeviceSigner.parseDeviceId(recordJson()))
    }

    @Test
    fun absentBlankOrMalformedRecordHasNoDeviceId() {
        assertNull(RuntimeDeviceSigner.parseDeviceId(null))
        assertNull(RuntimeDeviceSigner.parseDeviceId(""))
        assertNull(RuntimeDeviceSigner.parseDeviceId("not json"))
        assertNull(RuntimeDeviceSigner.parseDeviceId("""{"app_id":"x"}"""))
        assertNull(RuntimeDeviceSigner.parseDeviceId(recordJson(id = "  ")))
    }

    @Test
    fun readsTheRuntimeServiceAndAccount() {
        val p = FakePlatform()
        p.signer().deviceId(appId)
        assertEquals(listOf("synheart-core" to "device_record:com.example.app"), p.loads)
    }

    @Test
    fun identityNeedsBothRecordAndKey() {
        val p = FakePlatform()
        assertNull(p.signer().deviceId(appId))

        p.writeRecord()
        assertNull("record without key is not an identity", p.signer().deviceId(appId))

        p.store.clear()
        p.addKey(deviceId)
        assertNull("key without record is not an identity", p.signer().deviceId(appId))

        p.writeRecord()
        assertEquals(deviceId, p.signer().deviceId(appId))
    }

    @Test
    fun recordForAnotherAppIsNotUsed() {
        val p = FakePlatform()
        p.writeRecord()
        p.addKey(deviceId)
        assertNull(p.signer().deviceId("com.other.app"))
        assertNull(p.signer().sign("com.other.app", "POST", "/v1/hsi", null))
    }

    // ── signing ─────────────────────────────────────────────────────────

    @Test
    fun noRuntimeIdentityReturnsNullSoCallerFallsBack() {
        assertNull(FakePlatform().signer().sign(appId, "POST", "/v1/hsi", null))
    }

    @Test
    fun signsWithTheRuntimeKeyOverTheRuntimeMessage() {
        val p = FakePlatform()
        p.writeRecord()
        val kp = p.addKey(deviceId)
        val body = """{"hsi":1}""".toByteArray()

        val h = p.signer(nowSeconds = 1_712_345_678L).sign(appId, "post", "/v1/hsi", body)!!

        assertEquals(appId, h["appId"])
        assertEquals(deviceId, h["deviceId"])
        assertEquals("1712345678", h["timestamp"])
        assertEquals("nonce-1", h["nonce"])
        assertEquals("1", h["signatureVersion"])
        assertEquals(
            setOf("appId", "deviceId", "signature", "timestamp", "nonce", "signatureVersion"),
            h.keys,
        )

        // Standard base64 of DER, verifiable over exactly the runtime message.
        val der = Base64.getDecoder().decode(h["signature"])
        assertEquals(0x30, der[0].toInt() and 0xFF)
        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(kp.public)
            update(RuntimeDeviceSigner.buildMessage("POST", "/v1/hsi", 1_712_345_678L, body))
            verify(der)
        }
        assertTrue(ok)
    }

    @Test
    fun keystoreFailureIsAnErrorNotAFallback() {
        val p = FakePlatform()
        p.writeRecord()
        p.addKey(deviceId)
        p.failSigning = true
        assertFailsWith<RuntimeDeviceSigner.SigningFailed> {
            p.signer().sign(appId, "POST", "/v1/hsi", null)
        }
    }

    // ── clock ───────────────────────────────────────────────────────────

    @Test
    fun clockOffsetAppliesServerMinusLocal() {
        var now = 1_000_000L // ms
        val c = ClockOffset { now }
        assertEquals(1000L, c.correctedEpochSeconds())
        c.update(1_120.0) // server 120 s ahead
        assertEquals(1120L, c.correctedEpochSeconds())
        now += 5_000
        assertEquals(1125L, c.correctedEpochSeconds())
    }

    // ── the pre-fix path ────────────────────────────────────────────────

    /// The store 0.1.11 read exclusively. The plugin never calls
    /// `SynheartAuth.initialize`, and Dart `registerDevice` throws before
    /// reaching the channel, so on a host app this store is always empty and
    /// signing from it always fails — which is why it is now only a fallback.
    @Test
    fun nativeSdkStoreIsNeverPopulated() {
        val auth = SynheartAuth.shared
        auth.configure("https://example.invalid/auth")
        assertFalse(auth.isRegistered(appId))
        assertNull(auth.getDeviceId(appId))
        assertFailsWith<SynheartAuthError.NotRegistered> {
            auth.signRequest(appId, "POST", "/v1/hsi", "{}".toByteArray())
        }
    }
}
