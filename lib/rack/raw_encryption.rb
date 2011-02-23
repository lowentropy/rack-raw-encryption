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
      @app.call(env).tap do |arr|
        status, headers, body = arr
        arr[-1] = decrypt!(env, body) if decrypted_download?(env)
        thread.join if thread
      end
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
        encryptor = Processor.new :encrypt, key, input, output
        Thread.new(encryptor) do |enc|
          encryptor.run!
        end
      end
    end

    def decrypt!(env, body)
      if key = encryption_key(env)
        [].tap do |new_body|
          decryptor = Processor.new :decrypt, key
          body.each do |part|
            new_body << decryptor.update(part)
          end
          new_body << decryptor.final
        end
      else
        body
      end
    end
    
    def get_key_from_env(env)
      req = Rack::Request.new(env)
      env['HTTP_X_ENCRYPTION_KEY'] ||
      req.params['encryption_key']
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
      attr_reader :input, :output, :aes, :chunk_size
      def initialize(method, key, input = nil, output = nil, opts = {})
        @aes = construct_aes method, key
        @input, @output = input, output
        @chunk_size = opts[:chunk_size] || (1024 * 1024)
      end
      def run!
        advance! until done?
        finalize!
      end
      def update(chunk)
        aes.update chunk
      end
      def final
        aes.final
      end
      private
      def advance!
        @output << update(@chunk)
      end
      def finalize!
        @output << final
        @output.close
      end
      def done?
        next_chunk.nil?
      end
      def next_chunk
        @chunk = input.read(chunk_size)
      end
      def construct_aes(method, key)
        OpenSSL::Cipher::Cipher.new('aes-256-cbc').tap do |aes|
          aes.send method
          aes.key = key
        end
      end
    end
  end
end
