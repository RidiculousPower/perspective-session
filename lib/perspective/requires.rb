
require 'rack/request'
require 'rack/response'

# session id cookie is stored with base64 encoding
require 'base64'

# once decoded from base64, session id is encrypted
require 'openssl'

# encryption key is kept in persistence layer
require 'persistence'

basepath = 'session'

files = [

  'configuration',
  'rack'

]

files.each do |this_file|
  require_relative( File.join( basepath, this_file ) + '.rb' )
end
