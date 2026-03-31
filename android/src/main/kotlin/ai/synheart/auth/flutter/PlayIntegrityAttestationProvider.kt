package ai.synheart.auth.flutter

import android.content.Context
import android.util.Log
import ai.synheart.auth.registration.AttestationProvider
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/// Play Integrity API implementation of [AttestationProvider].
/// Generates an integrity token bound to the given nonce.
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

            suspendCancellableCoroutine { continuation ->
                integrityManager.requestIntegrityToken(request)
                    .addOnSuccessListener { response ->
                        val token = response.token()
                        Log.i(tag, "Play Integrity token obtained (${token.length} chars)")
                        continuation.resume(token)
                    }
                    .addOnFailureListener { e ->
                        Log.e(tag, "Play Integrity failed: ${e.javaClass.simpleName}: ${e.message}", e)
                        continuation.resume(null)
                    }
            }
        } catch (e: Exception) {
            Log.e(tag, "Play Integrity unavailable: ${e.javaClass.simpleName}: ${e.message}", e)
            null
        }
    }
}
