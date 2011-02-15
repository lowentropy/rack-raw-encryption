require 'openssl'
require 'stringio'
require 'rubygems'
require 'rack/test'
require 'shoulda'
require 'rack/raw_encryption'

class RawEncryptionTest < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    opts = @middleware_opts
    Rack::Builder.new do
      use Rack::RawEncryption, opts
      run Proc.new { |env| [200, {}, [env['rack.input'].read]] }
    end
  end

  def setup
    @middleware_opts = {
      :upload_paths => ['/encrypt', '/safe'],
      :download_paths => ['/decrypt', '/safe']
    }
    @key = 'asdkfjlasdf'
    @raw = File.read(__FILE__)
    @file = File.open(__FILE__)
  end

  def upload(env = {})
    env = {
      'REQUEST_METHOD' => 'POST',
      'CONTENT_TYPE' => 'application/octet-stream',
      'HTTP_X_ENCRYPTION_KEY' => @key,
      'rack.input' => @file,
    }.merge(env)
    request(env['PATH_INFO'], env)
  end

  context "normal request" do
    should "not encrypt or decrypt" do
      upload('PATH_INFO' => '/normal')
      assert_responds_with_plain_text
    end
  end
  
  context "encrypted upload" do
    should "encrypt the raw file" do
      upload('PATH_INFO' => '/encrypt')
      assert_responds_with_encrypted_text
    end
  end
  
  context "decrypted download" do
    should "decrypt the raw file" do
      upload('PATH_INFO' => '/decrypt', 'rack.input' => StringIO.new(encrypted))
      assert_responds_with_plain_text
    end
  end
  
  context "encryption plus decryption" do
    should "respond with plain text" do
      upload('PATH_INFO' => '/safe')
      assert_responds_with_plain_text
    end
  end
  
  def assert_responds_with_plain_text
    assert_equal @raw, last_response.body
  end
  
  def assert_responds_with_encrypted_text
    assert_equal encrypted, last_response.body
  end
  
  def encrypted
    aes = OpenSSL::Cipher::Cipher.new('aes-256-cbc')
    aes.encrypt
    aes.key = Digest::SHA256.digest @key
    aes.update(@raw) + aes.final
  end
  
  def assert_file_uploaded_as(file_type)
    file = File.open(@path)
    received = last_request.POST["file"]
    assert_equal file.gets, received[:tempfile].gets
    assert_equal file_type, received[:type]
    assert last_response.ok?
  end

  def assert_successful_non_upload
    assert ! last_request.POST.has_key?('file')
    assert last_response.ok?
  end
end
