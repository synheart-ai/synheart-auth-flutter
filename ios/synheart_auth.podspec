Pod::Spec.new do |s|
  s.name             = 'synheart_auth'
  s.version          = '0.1.13'
  s.summary          = 'Flutter plugin for Synheart device authentication.'
  s.description      = 'Wraps the native SynheartAuth iOS SDK (Secure Enclave) for Flutter.'
  s.homepage         = 'https://github.com/synheart-ai/synheart-auth-flutter'
  s.license          = { :type => 'Apache 2.0', :file => '../LICENSE' }
  s.author           = 'Synheart AI'
  s.source           = { :path => '.' }
  # Flutter glue only. Every `synheart_native_*` symbol the Dart side resolves
  # through `DynamicLibrary.process()` is defined by the `SynheartAuth` pod
  # (synheart-auth-swift, `Sources/SynheartAuth/FFI/SynheartNativeCrypto.swift`);
  # this plugin ships no crypto or Keychain code of its own. 0.1.3 is the
  # minimum: registration recovery, re-registration after key loss, and the
  # 0.1.2 Keychain absent-vs-unavailable fix. If trunk doesn't carry it yet,
  # pin it in the host Podfile:
  #   pod 'SynheartAuth', :git => 'https://github.com/synheart-ai/synheart-auth-swift.git', :tag => 'v0.1.3'
  s.source_files     = 'Classes/*.{h,m,swift}'
  s.dependency 'Flutter'
  s.dependency 'SynheartAuth', '>= 0.1.3'
  s.platform         = :ios, '15.0'
  s.swift_version    = '5.9'
end
