package ai.synheart.auth.flutter

import com.google.android.play.core.integrity.IntegrityServiceException
import com.google.android.play.core.integrity.model.IntegrityErrorCode

/// Maps Play Integrity failures onto the attestation reason vocabulary that
/// synheart-core-runtime understands.
///
/// The runtime used to see one indistinguishable "no attestation" for all of
/// these, and reported every one to the host as a permanent failure. Half of
/// them are transient and worth retrying in seconds; the other half will never
/// succeed on this device or until a developer fixes the Play Console setup, and
/// retrying those forever just burns battery.
///
/// The tokens here must stay in step with `AttestationReason` in
/// `crates/core-runtime/src/auth/types.rs` and with the table in the runtime's
/// `book/src/auth/platform.md`. An unrecognized token degrades to `unknown` on
/// the Rust side rather than failing, so adding one here is safe; changing the
/// spelling of an existing one is not.
internal object PlayIntegrityReasons {
    /// Retry shortly — the service was reachable but did not answer usefully.
    const val TRANSIENT = "transient"

    /// Our own bounded wait expired before any verdict arrived.
    const val TIMEOUT = "timeout"

    /// Rate limited. Retry, but not soon.
    const val QUOTA = "quota"

    /// This device can never attest. Fall back to local-only and stop asking.
    const val UNSUPPORTED = "unsupported"

    /// Broken until a developer fixes it: Play Console linkage, cloud project
    /// number, nonce construction, or missing initialization.
    const val MISCONFIGURED = "misconfigured"

    /// We genuinely do not know. Treated as non-retryable by the runtime.
    const val UNKNOWN = "unknown"

    /// Classify a Play Integrity error code.
    ///
    /// A code we have never seen maps to [UNKNOWN] rather than a guess: telling
    /// a host to retry forever, or to give up permanently, are both worse than
    /// admitting ignorance.
    fun forErrorCode(errorCode: Int?): String = when (errorCode) {
        null -> UNKNOWN

        // Reachable, but not right now.
        IntegrityErrorCode.NETWORK_ERROR,
        IntegrityErrorCode.GOOGLE_SERVER_UNAVAILABLE,
        IntegrityErrorCode.CLIENT_TRANSIENT_ERROR,
        IntegrityErrorCode.CANNOT_BIND_TO_SERVICE,
        IntegrityErrorCode.INTERNAL_ERROR -> TRANSIENT

        IntegrityErrorCode.TOO_MANY_REQUESTS -> QUOTA

        // The device lacks the machinery, and only the user can change that —
        // installing Play Store, updating it, signing in. Not something an app
        // retry will fix, so hosts should stop asking.
        IntegrityErrorCode.API_NOT_AVAILABLE,
        IntegrityErrorCode.PLAY_STORE_NOT_FOUND,
        IntegrityErrorCode.PLAY_SERVICES_NOT_FOUND,
        IntegrityErrorCode.PLAY_STORE_ACCOUNT_NOT_FOUND,
        IntegrityErrorCode.PLAY_STORE_VERSION_OUTDATED,
        IntegrityErrorCode.PLAY_SERVICES_VERSION_OUTDATED -> UNSUPPORTED

        // A developer has to fix something: Play Console linkage, the cloud
        // project number, or — for the nonce cases — our own request.
        IntegrityErrorCode.APP_NOT_INSTALLED,
        IntegrityErrorCode.APP_UID_MISMATCH,
        IntegrityErrorCode.CLOUD_PROJECT_NUMBER_IS_INVALID,
        IntegrityErrorCode.NONCE_TOO_SHORT,
        IntegrityErrorCode.NONCE_TOO_LONG,
        IntegrityErrorCode.NONCE_IS_NOT_BASE64 -> MISCONFIGURED

        else -> UNKNOWN
    }

    /// Classify anything thrown out of a Play Integrity call.
    ///
    /// Takes [Throwable], not [Exception], deliberately: when the Play Integrity
    /// artifact is missing or stripped by R8, the call throws
    /// `NoClassDefFoundError`, which is an `Error`. That used to escape into JNI
    /// and take the process down. It is a device that cannot attest, not a crash.
    fun forThrowable(t: Throwable): String = when (t) {
        is IntegrityServiceException -> forErrorCode(t.errorCode)
        is NoClassDefFoundError,
        is ClassNotFoundException,
        is UnsatisfiedLinkError -> UNSUPPORTED
        is SecurityException -> MISCONFIGURED
        else -> UNKNOWN
    }
}
