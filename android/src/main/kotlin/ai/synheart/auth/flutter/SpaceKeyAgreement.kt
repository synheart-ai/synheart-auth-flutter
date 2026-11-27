package ai.synheart.auth.flutter

import java.math.BigInteger
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/// Pure helpers for sync-space key agreement, kept free of Android APIs so the
/// JVM unit tests can reach them.
///
/// The runtime asks for P-256 ECDH with the key under `<device_id>.space.agreement`
/// (core-runtime 0.47.0, `synheart_core_sdk_set_key_agreement_callback`). Every
/// other alias, `<device_id>.space.content` included, is a signing key.
internal object SpaceKeyAgreement {
    const val AGREEMENT_ALIAS_SUFFIX = ".space.agreement"

    /// Whether [id] names a key-agreement key rather than a signing key.
    fun isAgreementAlias(id: String): Boolean = id.endsWith(AGREEMENT_ALIAS_SUFFIX)

    /// The peer's public key from an uncompressed P-256 point (65 bytes,
    /// `0x04` first) on the curve described by [params], or null when the
    /// bytes are not such a point. The on-curve check is explicit: not every
    /// provider rejects an off-curve point before the agreement.
    fun peerPublicKey(bytes: ByteArray, params: ECParameterSpec): ECPublicKey? {
        if (bytes.size != 65 || bytes[0] != 0x04.toByte()) return null
        val x = BigInteger(1, bytes.copyOfRange(1, 33))
        val y = BigInteger(1, bytes.copyOfRange(33, 65))
        if (!isOnCurve(x, y, params)) return null
        return try {
            KeyFactory.getInstance("EC")
                .generatePublic(ECPublicKeySpec(ECPoint(x, y), params)) as ECPublicKey
        } catch (e: Exception) {
            null
        }
    }

    /// y² = x³ + ax + b (mod p), with both coordinates in [0, p).
    internal fun isOnCurve(x: BigInteger, y: BigInteger, params: ECParameterSpec): Boolean {
        val field = params.curve.field as? ECFieldFp ?: return false
        val p = field.p
        if (x.signum() < 0 || x >= p || y.signum() < 0 || y >= p) return false
        val lhs = y.modPow(BigInteger.TWO, p)
        val rhs = x.modPow(BigInteger.valueOf(3), p)
            .add(params.curve.a.multiply(x))
            .add(params.curve.b)
            .mod(p)
        return lhs == rhs
    }
}
