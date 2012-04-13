require 'rack/request'
require 'rack/response'

# session id cookie is stored with base64 encoding
require 'base64'

# once decoded from base64, session id is encrypted
require 'openssl'

# encryption key is kept in persistence layer
require 'persistence'

require_relative '../../configuration/lib/magnets-configuration.rb'

module ::Magnets
  class Session
    module Configuration
    end
    module Rack
    end
  end
end

basepath = 'magnets-session/Magnets/Session'

files = [
  'Configuration',
  'Rack'
]

files.each do |this_file|
  require_relative( File.join( basepath, this_file ) + '.rb' )
end

require_relative( basepath + '.rb' )

::Magnets.extend( ::Magnets::Session::Rack )
::Magnets::Configuration.register_configuration( :session, ::Magnets::Session::Configuration )
