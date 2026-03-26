Pod::Spec.new do |s|
  s.name             = 'synheart_auth'
  s.version          = '1.0.0'
  s.summary          = 'Flutter plugin for Synheart device authentication.'
  s.description      = 'Wraps the native SynheartAuth iOS SDK (Secure Enclave) for Flutter.'
  s.homepage         = 'https://github.com/synheart/synheart-auth-dart'
  s.license          = { :type => 'Proprietary' }
  s.author           = 'Synheart'
  s.source           = { :path => '.' }
  # Keep this plugin self-contained by compiling all Swift sources under Classes.
  s.source_files     = 'Classes/**/*.{h,m,swift}'
  s.frameworks       = 'Security', 'DeviceCheck'
  s.dependency 'Flutter'
  s.platform         = :ios, '15.0'
  s.swift_version    = '5.9'
end
