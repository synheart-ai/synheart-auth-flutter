package ai.synheart.auth.flutter

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * JVM unit tests for the byte-level helpers in [NativeCryptoBridge].
 *
 * These guard the native runtime's FFI contract:
 *   - `sign_bytes` callback must return base64 of raw 64-byte `r||s`, never
 *     the DER form Android Keystore emits natively.
 *   - Public-key coordinates must be exactly 32 bytes, big-endian, no sign byte.
 *
 * Android-specific code paths (Keystore, Play Integrity, EncryptedSharedPreferences)
 * cannot run here; those are exercised in instrumentation tests or by the app.
 */
class NativeCryptoBridgeTest {

    // ── toUnsigned32 ────────────────────────────────────────────────────

    @Test
    fun `toUnsigned32 strips BigInteger sign byte when input is 33 bytes starting with 0x00`() {
        val input = ByteArray(33).also {
            it[0] = 0x00
            for (i in 1..32) it[i] = 0xFF.toByte()
        }
        val out = NativeCryptoBridge.toUnsigned32(input)
        assertEquals(32, out.size)
        for (i in 0..31) assertEquals("byte[$i]", 0xFF.toByte(), out[i])
    }

    @Test
    fun `toUnsigned32 left-pads short input to 32 bytes`() {
        val input = byteArrayOf(0x11, 0x22, 0x33)
        val out = NativeCryptoBridge.toUnsigned32(input)
        assertEquals(32, out.size)
        for (i in 0..28) assertEquals("pad[$i]", 0.toByte(), out[i])
        assertEquals(0x11.toByte(), out[29])
        assertEquals(0x22.toByte(), out[30])
        assertEquals(0x33.toByte(), out[31])
    }

    @Test
    fun `toUnsigned32 passes through exact 32-byte input unchanged`() {
        val input = ByteArray(32) { it.toByte() }
        assertArrayEquals(input, NativeCryptoBridge.toUnsigned32(input))
    }

    // ── derEcdsaToRawRS ─────────────────────────────────────────────────

    @Test
    fun `derEcdsaToRawRS rejects empty and non-SEQUENCE input`() {
        assertNull(NativeCryptoBridge.derEcdsaToRawRS(byteArrayOf()))
        assertNull(NativeCryptoBridge.derEcdsaToRawRS(byteArrayOf(0x00)))
        assertNull(NativeCryptoBridge.derEcdsaToRawRS(byteArrayOf(0x02, 0x01, 0x00))) // bare INTEGER
    }

    @Test
    fun `derEcdsaToRawRS strips leading sign byte from r and s integers`() {
        // SEQUENCE { INTEGER 0x00 || 0xFF*32, INTEGER 0x00 || 0xFE*32 } — both
        // integers carry the DER sign byte that the parser must drop before
        // returning the 64-byte r||s buffer.
        val r = ByteArray(33).also {
            it[0] = 0x00
            for (i in 1..32) it[i] = 0xFF.toByte()
        }
        val s = ByteArray(33).also {
            it[0] = 0x00
            for (i in 1..32) it[i] = 0xFE.toByte()
        }
        val der = buildDerSig(r, s)
        val raw = NativeCryptoBridge.derEcdsaToRawRS(der)!!
        assertEquals(64, raw.size)
        for (i in 0..31) assertEquals("r[$i]", 0xFF.toByte(), raw[i])
        for (i in 32..63) assertEquals("s[${i - 32}]", 0xFE.toByte(), raw[i])
    }

    @Test
    fun `derEcdsaToRawRS left-pads short integer values to 32 bytes`() {
        val r = byteArrayOf(0x11, 0x22, 0x33)
        val s = byteArrayOf(0x44, 0x55, 0x66, 0x77)
        val der = buildDerSig(r, s)
        val raw = NativeCryptoBridge.derEcdsaToRawRS(der)!!
        assertEquals(64, raw.size)
        for (i in 0..28) assertEquals("r-pad[$i]", 0.toByte(), raw[i])
        assertEquals(0x11.toByte(), raw[29])
        assertEquals(0x22.toByte(), raw[30])
        assertEquals(0x33.toByte(), raw[31])
        for (i in 32..59) assertEquals("s-pad[$i]", 0.toByte(), raw[i])
        assertEquals(0x44.toByte(), raw[60])
        assertEquals(0x77.toByte(), raw[63])
    }

    @Test
    fun `derEcdsaToRawRS round-trips real JDK ECDSA signatures and preserves r and s`() {
        // Generate a P-256 keypair, sign the same message N times (ECDSA is
        // non-deterministic so each run exercises a different r/s distribution),
        // pass every DER output through our parser, re-DER-encode using a
        // minimal builder, and verify with the JDK. This is the test that
        // would have caught the original "base64(raw DER)" bug: it proves r
        // and s are the actual signature scalars, not mis-aligned bytes.
        val gen = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        val kp = gen.generateKeyPair()
        val publicKey = kp.public as ECPublicKey

        val message = "hello synheart".toByteArray()
        val signer = Signature.getInstance("SHA256withECDSA")
        val verifier = Signature.getInstance("SHA256withECDSA")

        repeat(16) {
            signer.initSign(kp.private)
            signer.update(message)
            val der = signer.sign()

            val raw = NativeCryptoBridge.derEcdsaToRawRS(der)
            assertNotNull("parse should succeed for real DER signature", raw)
            assertEquals(64, raw!!.size)

            val rebuilt = buildDerSigFromFixed32(
                r = raw.copyOfRange(0, 32),
                s = raw.copyOfRange(32, 64),
            )
            verifier.initVerify(publicKey)
            verifier.update(message)
            assertTrue(
                "signature rebuilt from parser output must verify against original pubkey",
                verifier.verify(rebuilt),
            )
        }
    }

    // ── test helpers ────────────────────────────────────────────────────

    /** Build DER SEQUENCE of two INTEGERs using the given bytes verbatim. */
    private fun buildDerSig(r: ByteArray, s: ByteArray): ByteArray {
        val body = byteArrayOf(0x02, r.size.toByte()) + r +
            byteArrayOf(0x02, s.size.toByte()) + s
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    /**
     * Wrap two fixed-width 32-byte integers as a DER SEQUENCE, prefixing a
     * 0x00 sign byte when the high bit is set (matches JDK `SHA256withECDSA`
     * output semantics, so the rebuilt signature verifies correctly).
     */
    private fun buildDerSigFromFixed32(r: ByteArray, s: ByteArray): ByteArray {
        fun toDerInt(v: ByteArray): ByteArray {
            var start = 0
            while (start < v.size - 1 &&
                v[start] == 0x00.toByte() &&
                (v[start + 1].toInt() and 0x80) == 0) start++
            val trimmed = v.copyOfRange(start, v.size)
            return if ((trimmed[0].toInt() and 0x80) != 0) {
                byteArrayOf(0x00) + trimmed
            } else {
                trimmed
            }
        }
        val rInt = toDerInt(r)
        val sInt = toDerInt(s)
        val body = byteArrayOf(0x02, rInt.size.toByte()) + rInt +
            byteArrayOf(0x02, sInt.size.toByte()) + sInt
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
