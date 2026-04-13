// RFC-CORE-0008: C-callable crypto bridge for Android.
//
// Exports five symbols that dart:ffi (PlatformNativeSdkCryptoCallbacks) looks
// up via DynamicLibrary.open('libsynheart_native_crypto.so'):
//
//   synheart_native_generate_key
//   synheart_native_sign_bytes
//   synheart_native_get_attestation
//   synheart_native_key_exists
//   synheart_native_delete_key
//
// Each function uses JNI to call NativeCryptoBridge (Kotlin) which delegates
// to Android Keystore / Play Integrity. Returned C strings are allocated with
// strdup() and MUST be freed by the caller.

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>

#define TAG "SynheartNativeBridge"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ── Cached JVM and class references ─────────────────────────────────

static JavaVM *g_jvm = nullptr;
static jclass  g_bridgeClass = nullptr;  // Global ref, valid across threads.

// Called automatically when the .so is loaded by System.loadLibrary().
// Runs on the main thread with the correct ClassLoader, so FindClass works.
extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void * /*reserved*/) {
    g_jvm = vm;

    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        LOGE("JNI_OnLoad: GetEnv failed");
        return JNI_VERSION_1_6;
    }

    // Cache NativeCryptoBridge class as a global ref so background threads
    // (e.g., Rust) can call static methods without needing the app ClassLoader.
    jclass local = env->FindClass("ai/synheart/auth/flutter/NativeCryptoBridge");
    if (local) {
        g_bridgeClass = (jclass) env->NewGlobalRef(local);
        env->DeleteLocalRef(local);
        LOGI("JNI_OnLoad: NativeCryptoBridge class cached");
    } else {
        LOGE("JNI_OnLoad: NativeCryptoBridge class not found — native crypto will fail");
        env->ExceptionClear();
    }

    LOGI("JNI_OnLoad: JavaVM cached");
    return JNI_VERSION_1_6;
}

// ── JNI helpers ─────────────────────────────────────────────────────────

// Attach current thread to JVM if needed. Returns the JNIEnv and whether
// we attached (and therefore must detach when done).
struct JniScope {
    JNIEnv *env;
    bool    attached;
};

static JniScope attach() {
    JniScope s{nullptr, false};
    if (!g_jvm) {
        LOGE("attach: g_jvm is null");
        return s;
    }
    jint rc = g_jvm->GetEnv(reinterpret_cast<void **>(&s.env), JNI_VERSION_1_6);
    if (rc == JNI_EDETACHED) {
        rc = g_jvm->AttachCurrentThread(&s.env, nullptr);
        if (rc == JNI_OK) s.attached = true;
        else LOGE("AttachCurrentThread failed: %d", rc);
    }
    return s;
}

static void detach(JniScope &s) {
    if (s.attached && g_jvm) {
        g_jvm->DetachCurrentThread();
        s.attached = false;
    }
}

// Return the cached NativeCryptoBridge class (global ref from JNI_OnLoad).
static jclass findBridgeClass(JNIEnv * /*env*/) {
    if (!g_bridgeClass) {
        LOGE("findBridgeClass: g_bridgeClass is null (JNI_OnLoad failed?)");
    }
    return g_bridgeClass;
}

// Convert jstring → strdup'd C string (caller must free). Returns NULL on failure.
static char *jstringToStrdup(JNIEnv *env, jstring js) {
    if (!js) return nullptr;
    const char *utf = env->GetStringUTFChars(js, nullptr);
    if (!utf) return nullptr;
    char *dup = strdup(utf);
    env->ReleaseStringUTFChars(js, utf);
    return dup;
}

// ── Exported symbols ────────────────────────────────────────────────────

extern "C" {

// Generate P-256 key pair. Returns JSON: {"x":"<b64url>","y":"<b64url>"} or NULL.
__attribute__((visibility("default")))
char *synheart_native_generate_key(const char *device_id) {
    JniScope s = attach();
    if (!s.env) return nullptr;

    jclass cls = findBridgeClass(s.env);
    if (!cls) { detach(s); return nullptr; }

    jmethodID mid = s.env->GetStaticMethodID(cls, "generateKey",
        "(Ljava/lang/String;)Ljava/lang/String;");
    if (!mid) { s.env->ExceptionClear(); detach(s); return nullptr; }

    jstring jDeviceId = s.env->NewStringUTF(device_id);
    jstring result = (jstring) s.env->CallStaticObjectMethod(cls, mid, jDeviceId);

    if (s.env->ExceptionCheck()) {
        LOGE("synheart_native_generate_key: JNI exception");
        s.env->ExceptionDescribe();
        s.env->ExceptionClear();
        detach(s);
        return nullptr;
    }

    char *out = jstringToStrdup(s.env, result);
    detach(s);
    return out;
}

// Sign raw bytes. Returns base64url-encoded R||S signature or NULL.
__attribute__((visibility("default")))
char *synheart_native_sign_bytes(const char *device_id,
                                  const unsigned char *data,
                                  int data_len) {
    JniScope s = attach();
    if (!s.env) return nullptr;

    jclass cls = findBridgeClass(s.env);
    if (!cls) { detach(s); return nullptr; }

    jmethodID mid = s.env->GetStaticMethodID(cls, "signBytes",
        "(Ljava/lang/String;[B)Ljava/lang/String;");
    if (!mid) { s.env->ExceptionClear(); detach(s); return nullptr; }

    jstring  jDeviceId = s.env->NewStringUTF(device_id);
    jbyteArray jData   = s.env->NewByteArray(data_len);
    s.env->SetByteArrayRegion(jData, 0, data_len, reinterpret_cast<const jbyte *>(data));

    jstring result = (jstring) s.env->CallStaticObjectMethod(cls, mid, jDeviceId, jData);

    if (s.env->ExceptionCheck()) {
        LOGE("synheart_native_sign_bytes: JNI exception");
        s.env->ExceptionDescribe();
        s.env->ExceptionClear();
        detach(s);
        return nullptr;
    }

    char *out = jstringToStrdup(s.env, result);
    detach(s);
    return out;
}

// Get attestation. Returns JSON: {"format":"play-integrity","blob":"<raw token>"} or NULL.
__attribute__((visibility("default")))
char *synheart_native_get_attestation(const char *device_id,
                                       const unsigned char *hash_ptr,
                                       int hash_len) {
    JniScope s = attach();
    if (!s.env) return nullptr;

    jclass cls = findBridgeClass(s.env);
    if (!cls) { detach(s); return nullptr; }

    jmethodID mid = s.env->GetStaticMethodID(cls, "getAttestation",
        "(Ljava/lang/String;[B)Ljava/lang/String;");
    if (!mid) { s.env->ExceptionClear(); detach(s); return nullptr; }

    jstring  jDeviceId = s.env->NewStringUTF(device_id);
    jbyteArray jHash   = s.env->NewByteArray(hash_len);
    s.env->SetByteArrayRegion(jHash, 0, hash_len, reinterpret_cast<const jbyte *>(hash_ptr));

    jstring result = (jstring) s.env->CallStaticObjectMethod(cls, mid, jDeviceId, jHash);

    if (s.env->ExceptionCheck()) {
        LOGE("synheart_native_get_attestation: JNI exception");
        s.env->ExceptionDescribe();
        s.env->ExceptionClear();
        detach(s);
        return nullptr;
    }

    char *out = jstringToStrdup(s.env, result);
    detach(s);
    return out;
}

// Check if key exists. Returns 1 if yes, 0 if no.
__attribute__((visibility("default")))
int synheart_native_key_exists(const char *device_id) {
    JniScope s = attach();
    if (!s.env) return 0;

    jclass cls = findBridgeClass(s.env);
    if (!cls) { detach(s); return 0; }

    jmethodID mid = s.env->GetStaticMethodID(cls, "keyExists",
        "(Ljava/lang/String;)Z");
    if (!mid) { s.env->ExceptionClear(); detach(s); return 0; }

    jstring jDeviceId = s.env->NewStringUTF(device_id);
    jboolean result = s.env->CallStaticBooleanMethod(cls, mid, jDeviceId);

    if (s.env->ExceptionCheck()) {
        s.env->ExceptionDescribe();
        s.env->ExceptionClear();
        detach(s);
        return 0;
    }

    detach(s);
    return result ? 1 : 0;
}

// Delete key. Returns 0 on success, 1 on failure.
__attribute__((visibility("default")))
int synheart_native_delete_key(const char *device_id) {
    JniScope s = attach();
    if (!s.env) return 1;

    jclass cls = findBridgeClass(s.env);
    if (!cls) { detach(s); return 1; }

    jmethodID mid = s.env->GetStaticMethodID(cls, "deleteKey",
        "(Ljava/lang/String;)Z");
    if (!mid) { s.env->ExceptionClear(); detach(s); return 1; }

    jstring jDeviceId = s.env->NewStringUTF(device_id);
    jboolean result = s.env->CallStaticBooleanMethod(cls, mid, jDeviceId);

    if (s.env->ExceptionCheck()) {
        s.env->ExceptionDescribe();
        s.env->ExceptionClear();
        detach(s);
        return 1;
    }

    detach(s);
    return result ? 0 : 1;
}

} // extern "C"
