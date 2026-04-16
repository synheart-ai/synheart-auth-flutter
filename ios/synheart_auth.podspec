Pod::Spec.new do |s|
  s.name             = 'synheart_auth'
  s.version          = '0.1.0'
  s.summary          = 'Flutter plugin for Synheart device authentication.'
  s.description      = 'Wraps the native SynheartAuth iOS SDK (Secure Enclave) for Flutter.'
  s.homepage         = 'https://github.com/synheart/synheart-auth-flutter'
  s.license          = { :type => 'Proprietary' }
  s.author           = 'Synheart'
  s.source           = { :path => '.' }
  # Flutter glue only. Core auth logic (Secure Enclave, Keychain, network,
  # @_cdecl FFI shims) lives in the SynheartAuth pod/SwiftPM package.
  s.source_files     = 'Classes/*.{h,m,swift}'
  s.dependency 'Flutter'
  s.dependency 'SynheartAuth'
  s.platform         = :ios, '15.0'
  s.swift_version    = '5.9'
end
