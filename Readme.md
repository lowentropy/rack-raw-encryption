# Rack Raw Encryption Middleware

This rack layer intercepts raw file uploads/downloads and applies
AES-256-CBC encryption to the contents. Used in combination with
[rack-raw-upload][https://github.com/newbamboo/rack-raw-upload],
you can get normal file uploads (using <pre>params[:file]</pre>)
which are transparently encrypted.
