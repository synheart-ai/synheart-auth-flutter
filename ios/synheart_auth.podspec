Pod::Spec.new do |s|
  s.name             = 'synheart_auth'
  s.version          = '0.1.3'
  s.summary          = 'Flutter plugin for Synheart device authentication.'
  s.description      = 'Wraps the native SynheartAuth iOS SDK (Secure Enclave) for Flutter.'
  s.homepage         = 'https://github.com/synheart-ai/synheart-auth-flutter'
  s.license          = { :type => 'Apache 2.0', :file => '../LICENSE' }
  s.author           = 'Synheart AI'
  s.source           = { :path => '.' }
  # Flutter glue only. The native SynheartAuth iOS SDK (Secure Enclave,
  # Keychain, network) is consumed via SwiftPM from
  # https://github.com/synheart-ai/synheart-auth-swift and added to the
  # host app's Package dependencies.
  s.source_files     = 'Classes/*.{h,m,swift}'
  s.dependency 'Flutter'
  s.dependency 'SynheartAuth'
  s.platform         = :ios, '15.0'
  s.swift_version    = '5.9'
end
