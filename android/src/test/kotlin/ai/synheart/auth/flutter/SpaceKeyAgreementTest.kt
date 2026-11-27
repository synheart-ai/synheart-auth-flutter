package ai.synheart.auth.flutter

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SpaceKeyAgreementTest {

    private fun p256(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()

    /// 0x04 ‖ x32 ‖ y32, as the runtime passes a peer.
    private fun uncompressed(pub: ECPublicKey): ByteArray {
        fun fixed32(v: BigInteger): ByteArray {
            val b = v.toByteArray()
            return when {
                b.size == 32 -> b
                b.size > 32 -> b.copyOfRange(b.size - 32, b.size)
                else -> ByteArray(32 - b.size) + b
            }
        }
        return byteArrayOf(0x04) + fixed32(pub.w.affineX) + fixed32(pub.w.affineY)
    }

    @Test
    fun onlyTheAgreementAliasIsAnAgreementKey() {
        assertTrue(SpaceKeyAgreement.isAgreementAlias("3f2a9c1e.space.agreement"))
        assertFalse(SpaceKeyAgreement.isAgreementAlias("3f2a9c1e"))
        assertFalse(SpaceKeyAgreement.isAgreementAlias("3f2a9c1e.space.content"))
        assertFalse(SpaceKeyAgreement.isAgreementAlias("3f2a9c1e.space.agreement.old"))
    }

    @Test
    fun peerMustBeAnUncompressedPointOnTheCurve() {
        val pub = p256().public as ECPublicKey
        val point = uncompressed(pub)
        assertNotNull(SpaceKeyAgreement.peerPublicKey(point, pub.params))

        assertNull(SpaceKeyAgreement.peerPublicKey(point.copyOf(64), pub.params), "64 bytes")
        val compressed = point.copyOf().also { it[0] = 0x02 }
        assertNull(SpaceKeyAgreement.peerPublicKey(compressed, pub.params), "not 0x04")
        val offCurve = point.copyOf().also { it[64] = (it[64].toInt() xor 1).toByte() }
        assertNull(SpaceKeyAgreement.peerPublicKey(offCurve, pub.params), "not on the curve")
    }

    @Test
    fun bothSidesDeriveTheSame32ByteSecret() {
        val a = p256()
        val b = p256()
        val params = (a.public as ECPublicKey).params

        fun agree(own: KeyPair, other: KeyPair): ByteArray {
            val peer = SpaceKeyAgreement.peerPublicKey(uncompressed(other.public as ECPublicKey), params)!!
            return KeyAgreement.getInstance("ECDH").run {
                init(own.private)
                doPhase(peer, true)
                generateSecret()
            }
        }

        val ab = agree(a, b)
        val ba = agree(b, a)
        assertEquals(32, ab.size)
        assertContentEquals(ab, ba)
    }
}
