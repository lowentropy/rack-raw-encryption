require 'openssl'

module Rack
  class RawEncryption

    def initialize(app, opts = {})
      @app = app
      @upload_paths = Array(opts[:upload_paths])
      @download_paths = Array(opts[:download_paths])
      @tmpdir = opts[:tmpdir] || Dir::tmpdir
    end

    def call(env)
      thread = replace_input!(env) if encrypted_upload?(env)
      status, headers, body = @app.call(env)
      body = decrypt!(env, body)   if decrypted_download?(env)
      thread.join if thread
      [status, headers, body]
    end

    private

    def upload_path?(request_path)
      any_path_match? request_path, @upload_paths
    end
    
    def download_path?(request_path)
      any_path_match? request_path, @download_paths
    end

    def any_path_match?(request_path, paths)
      paths.any? do |candidate|
        literal_path_match?(request_path, candidate) ||
        wildcard_path_match?(request_path, candidate)
      end
    end
    
    def encrypted_upload?(env)
      upload_path?(env['PATH_INFO'])
    end
    
    def decrypted_download?(env)
      download_path?(env['PATH_INFO'])
    end
    
    def replace_input!(env)
      if key = encryption_key(env)
        input = env['rack.input']
        env['rack.input'], output = IO.pipe
        enc = Encrypter.new key, input, output
        Thread.new { enc.run! }
      end
    end

    def decrypt!(env, body)
      if key = encryption_key(env)
        DecryptedBody.new key, body
      else
        body
      end
    end
    
    def get_key_from_env(env)
      env['HTTP_X_ENCRYPTION_KEY'] || Rack::Request.new(env).params['encryption_key']
    end

    def encryption_key(env)
      if key = get_key_from_env(env)
        Digest::SHA256.digest key
      end
    end

    def literal_path_match?(request_path, candidate)
      candidate == request_path
    end

    def wildcard_path_match?(request_path, candidate)
      return false unless candidate.include?('*')
      regexp = '^' + candidate.gsub('.', '\.').gsub('*', '[^/]*') + '$'
      !! (Regexp.new(regexp) =~ request_path)
    end
    
    class Processor
      attr_reader :aes
      def initialize(method, key)
        @aes = construct_aes method, key
      end
      private
      def construct_aes(method, key)
        OpenSSL::Cipher::Cipher.new('aes-256-cbc').tap do |aes|
          aes.send method
          aes.key = key
        end
      end
    end
    
    class Encrypter < Processor
      attr_reader :input, :output, :chunk_size
      def initialize(key, input = nil, output = nil, opts = {})
        super :encrypt, key
        @input, @output = input, output
        @chunk_size = opts[:chunk_size] || (1024 * 1024)
      end
      def run!
        advance! until done?
        finalize!
      end
      private
      def advance!
        @output << aes.update(@chunk)
      end
      def finalize!
        @output << aes.final
        @output.close
      end
      def done?
        next_chunk.nil?
      end
      def next_chunk
        @chunk = input.read(chunk_size)
      end
    end
    
    class DecryptedBody < Processor
      attr_reader :body
      def initialize(key, body)
        super :decrypt, key
        @body = body
      end
      def each
        body.each do |part|
          yield aes.update(part)
        end
        yield aes.final
      end
    end
    
  end
end
