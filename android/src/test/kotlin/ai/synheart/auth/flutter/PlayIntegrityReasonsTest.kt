package ai.synheart.auth.flutter

import com.google.android.play.core.integrity.model.IntegrityErrorCode
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * JVM unit tests for the Play Integrity → attestation reason mapping.
 *
 * The mapping is what decides whether a host retries in five seconds, waits
 * fifteen minutes, or stops asking altogether. Getting a code into the wrong
 * bucket is silent: registration simply behaves badly on some devices and not
 * others, with nothing in the logs to say why.
 *
 * `IntegrityErrorCode` is a plain constants class, so this runs without an
 * Android runtime.
 */
class PlayIntegrityReasonsTest {

    @Test
    fun `service outages and blips are transient`() {
        for (code in listOf(
            IntegrityErrorCode.NETWORK_ERROR,
            IntegrityErrorCode.GOOGLE_SERVER_UNAVAILABLE,
            IntegrityErrorCode.CLIENT_TRANSIENT_ERROR,
            IntegrityErrorCode.CANNOT_BIND_TO_SERVICE,
            IntegrityErrorCode.INTERNAL_ERROR,
        )) {
            assertEquals(
                "error code $code should be retryable",
                PlayIntegrityReasons.TRANSIENT,
                PlayIntegrityReasons.forErrorCode(code),
            )
        }
    }

    @Test
    fun `rate limiting is its own bucket so the backoff can be longer`() {
        assertEquals(
            PlayIntegrityReasons.QUOTA,
            PlayIntegrityReasons.forErrorCode(IntegrityErrorCode.TOO_MANY_REQUESTS),
        )
    }

    @Test
    fun `devices without the Play machinery are unsupported, not misconfigured`() {
        // Nothing a developer or a retry can fix — only the user, by installing
        // or updating Play Store. Hosts should fall back and stop asking.
        for (code in listOf(
            IntegrityErrorCode.API_NOT_AVAILABLE,
            IntegrityErrorCode.PLAY_STORE_NOT_FOUND,
            IntegrityErrorCode.PLAY_SERVICES_NOT_FOUND,
            IntegrityErrorCode.PLAY_STORE_ACCOUNT_NOT_FOUND,
            IntegrityErrorCode.PLAY_STORE_VERSION_OUTDATED,
            IntegrityErrorCode.PLAY_SERVICES_VERSION_OUTDATED,
        )) {
            assertEquals(
                "error code $code should be unsupported",
                PlayIntegrityReasons.UNSUPPORTED,
                PlayIntegrityReasons.forErrorCode(code),
            )
        }
    }

    @Test
    fun `setup faults are misconfigured so a developer sees them`() {
        for (code in listOf(
            IntegrityErrorCode.APP_NOT_INSTALLED,
            IntegrityErrorCode.APP_UID_MISMATCH,
            IntegrityErrorCode.CLOUD_PROJECT_NUMBER_IS_INVALID,
            IntegrityErrorCode.NONCE_TOO_SHORT,
            IntegrityErrorCode.NONCE_TOO_LONG,
            IntegrityErrorCode.NONCE_IS_NOT_BASE64,
        )) {
            assertEquals(
                "error code $code should be misconfigured",
                PlayIntegrityReasons.MISCONFIGURED,
                PlayIntegrityReasons.forErrorCode(code),
            )
        }
    }

    @Test
    fun `an unrecognised code admits ignorance rather than guessing`() {
        // Telling a host to retry forever and telling it to give up permanently
        // are both worse than "unknown", which the runtime treats as terminal
        // but without claiming to know why.
        assertEquals(PlayIntegrityReasons.UNKNOWN, PlayIntegrityReasons.forErrorCode(-4242))
        assertEquals(PlayIntegrityReasons.UNKNOWN, PlayIntegrityReasons.forErrorCode(null))
        assertEquals(
            PlayIntegrityReasons.UNKNOWN,
            PlayIntegrityReasons.forErrorCode(IntegrityErrorCode.NO_ERROR),
        )
    }

    /**
     * A missing or R8-stripped Play Integrity artifact throws
     * `NoClassDefFoundError`, which is an `Error`, not an `Exception`. It used
     * to escape `getAttestation` into JNI and take the process down.
     */
    @Test
    fun `a missing Play Integrity artifact is an unsupported device, not a crash`() {
        assertEquals(
            PlayIntegrityReasons.UNSUPPORTED,
            PlayIntegrityReasons.forThrowable(NoClassDefFoundError("IntegrityManagerFactory")),
        )
        assertEquals(
            PlayIntegrityReasons.UNSUPPORTED,
            PlayIntegrityReasons.forThrowable(ClassNotFoundException("IntegrityManagerFactory")),
        )
        assertEquals(
            PlayIntegrityReasons.UNSUPPORTED,
            PlayIntegrityReasons.forThrowable(UnsatisfiedLinkError("no native lib")),
        )
    }

    @Test
    fun `a permissions failure is a setup problem`() {
        assertEquals(
            PlayIntegrityReasons.MISCONFIGURED,
            PlayIntegrityReasons.forThrowable(SecurityException("no permission")),
        )
    }

    @Test
    fun `an unclassifiable throwable is unknown`() {
        assertEquals(
            PlayIntegrityReasons.UNKNOWN,
            PlayIntegrityReasons.forThrowable(IllegalStateException("boom")),
        )
    }

    /**
     * These tokens are a wire contract with `AttestationReason` in
     * synheart-core-runtime (`crates/core-runtime/src/auth/types.rs`). Renaming
     * one here degrades it to "unknown" on the Rust side — silently.
     */
    @Test
    fun `reason tokens match the runtime vocabulary`() {
        assertEquals("transient", PlayIntegrityReasons.TRANSIENT)
        assertEquals("timeout", PlayIntegrityReasons.TIMEOUT)
        assertEquals("quota", PlayIntegrityReasons.QUOTA)
        assertEquals("unsupported", PlayIntegrityReasons.UNSUPPORTED)
        assertEquals("misconfigured", PlayIntegrityReasons.MISCONFIGURED)
        assertEquals("unknown", PlayIntegrityReasons.UNKNOWN)
    }
}
