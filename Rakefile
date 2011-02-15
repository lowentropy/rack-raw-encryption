require 'rake/testtask'

task :default => :test

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    # gem is a Gem::Specification... see http://docs.rubygems.org/read/chapter/20 for more options
    gem.name = "rack-raw-encryption"
    gem.summary = %{Rack Raw File Encryption/Decryption Middleware}
    gem.description = %{Middleware that encrypts uploads and decrypts downloads of files with mimetype application/octet-stream.}
    gem.email = "lowentropy@gmail.com"
    gem.homepage = "https://github.com/lowentropy/rack-raw-encryption"
    gem.authors = ["Nathan Matthews"]
    gem.add_development_dependency 'rake'
    gem.add_development_dependency 'rack-test'
    gem.add_development_dependency 'shoulda'
  end
rescue LoadError
end

Rake::TestTask.new do |t|
  t.libs << "test"
  t.test_files = FileList['test/*_test.rb']
  t.verbose = true
end

begin
  require 'yard'
  YARD::Rake::YardocTask.new(:yardoc)
rescue LoadError
  task :yardoc do
    abort "YARD is not available. In order to run yard, you must: sudo gem install yard"
  end
end
