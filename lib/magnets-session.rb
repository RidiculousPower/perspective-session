require 'rack/request'
require 'rack/response'

# session id cookie is stored with base64 encoding
require 'base64'

# once decoded from base64, session id is encrypted
require 'openssl'

# encryption key is kept in persistence layer
require 'persistence'

require_relative '../../lib/rmagnets.rb'

module Rmagnets
  class Session
  end
end

require_relative 'rmagnets-session/Rmagnets/Session.rb'
