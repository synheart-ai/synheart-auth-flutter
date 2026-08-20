package ai.synheart.auth.flutter

import android.content.Context
import android.util.Log
import ai.synheart.auth.registration.AttestationProvider
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

/// Play Integrity API implementation of [AttestationProvider].
/// Generates an integrity token bound to the given nonce.
///
/// This serves the **MethodChannel** auth stack (`ai.synheart.auth`, wired in
/// SynheartAuthPlugin). [NativeCryptoBridge.getAttestation] serves the **JNI**
/// stack that synheart-core-runtime calls. The two look like duplicates and are
/// not — deleting either breaks one of the paths.
///
/// The reason vocabulary that [NativeCryptoBridge] reports is not available
/// here: [AttestationProvider.generateProof] returns `String?`, so there is
/// nowhere to put it without changing that SDK's interface.
class PlayIntegrityAttestationProvider(
    private val context: Context
) : AttestationProvider {
    private val tag = "SynheartPlayIntegrity"

    override suspend fun generateProof(nonce: String): String? {
        Log.i(tag, "Requesting Play Integrity token (nonce=${nonce.take(16)}...)")
        return try {
            val integrityManager = IntegrityManagerFactory.create(context)
            val request = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .build()

            // A stalled IntegrityService bind (no Play Store / unlinked package /
            // sideloaded build) can leave both listeners un-invoked forever.
            // Cap the wait so a hung bind resolves to null (attestation
            // unavailable) instead of suspending registration indefinitely.
            val token = withTimeoutOrNull(INTEGRITY_TIMEOUT_MS) {
                suspendCancellableCoroutine { continuation ->
                    integrityManager.requestIntegrityToken(request)
                        .addOnSuccessListener { response ->
                            val t = response.token()
                            Log.i(tag, "Play Integrity token obtained (${t.length} chars)")
                            continuation.resume(t)
                        }
                        .addOnFailureListener { e ->
                            Log.e(tag, "Play Integrity failed: ${e.javaClass.simpleName}: ${e.message}", e)
                            continuation.resume(null)
                        }
                }
            }
            if (token == null) {
                Log.e(tag, "Play Integrity timed out after ${INTEGRITY_TIMEOUT_MS}ms — returning null")
            }
            token
        } catch (t: Throwable) {
            // Throwable, not Exception: a missing or R8-stripped Play Integrity
            // artifact throws NoClassDefFoundError, which is an Error and would
            // otherwise propagate out of a call whose contract is "null when
            // attestation is unavailable".
            val reason = PlayIntegrityReasons.forThrowable(t)
            Log.e(tag, "Play Integrity unavailable (reason=$reason): ${t.javaClass.simpleName}: ${t.message}", t)
            null
        }
    }

    private companion object {
        /// Hard cap on the Play Integrity token request. See
        /// NativeCryptoBridge.INTEGRITY_TIMEOUT_SECONDS for rationale.
        private const val INTEGRITY_TIMEOUT_MS = 30_000L
    }
}
