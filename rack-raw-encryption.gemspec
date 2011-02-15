lib     = File.expand_path("../lib/rack/raw_encryption.rb", __FILE__)
version = File.read(lib)[/^\s*VERSION\s*=\s*(['"])(\d\.\d\.\d+)\1/, 2]

Gem::Specification.new do |spec|
  spec.name = 'rack-raw-encryption'
  spec.authors = "Nathan Matthews"
  spec.email = "lowentropy@gmail.com"
  spec.homepage = 'https://github.com/lowentropy/rack-raw-encryption'
  spec.summary = %{Rack Raw File Encryption/Decryption Middleware}
  spec.description = %{Middleware that encrypts uploads and decrypts downloads of files with mimetype application/octet-stream.}
  spec.extra_rdoc_files = %w{LICENSE README.md}
  spec.rdoc_options << "--charset=UTF-8" <<
                       "--main" << "README.rdoc"
  spec.version = version
  spec.files = Dir["{lib,test}/**/*.rb"] + spec.extra_rdoc_files + %w{Gemfile Gemfile.lock}
  spec.test_files = spec.files.grep(/^test\/.*test_.*\.rb$/)

  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rack-test'
  spec.add_development_dependency 'shoulda'
end
