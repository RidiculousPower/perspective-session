require 'rack/request'
require 'rack/response'

# session id cookie is stored with base64 encoding
require 'base64'

# once decoded from base64, session id is encrypted
require 'openssl'

# encryption key is kept in persistence layer
require_relative '../../../../../../rpersistence/lib/rpersistence.rb'

#######################
#  Rmagnets::Session  #
#######################

class Rmagnets::Session

       #---------------------#
  #####|  Rmagnets::Session  |##########################################################################
  #    #---------------------#                                                                         #
  #                                                                                                    #
  #  The purpose of the session is to sustain state between requests.                                  #
  #  State is stored in a storage port because the session is a bad location to store state.           #
  #  The session should therefore do the absolute minimum necessary to enable persistent references,   #
  #  while doing the maximum to protect the intended persistence of those references.                  #
  #                                                                                                    #
  #  Minimal requirements:                                                                             #
  #  * an ID                                                                                           #
  #  * cookie storage                                                                                  #
  #  * encryption/decryption for cookie                                                                #
  #                                                                                                    #
  #  We add to these requirements the ability to specify:                                              #
  #  * session domain                                                                                  #
  #  * session path (most specific path takes precedence)                                              #
  #  * expiration                                                                                      #
  #  * overlapping sessions                                                                            #
  #                                                                                                    #
  #  The only point that issues any complication is overlapping sessions.                              #
  #                                                                                                    #
  #  Multiple, simultaneous, overlapping sessions can be simply accomplished by moving from a single   #
  #  session ID to an array of session ID "frames".                                                    #
  #                                                                                                    #
  #  The last frame in the array will be considered the current session ID, and session state          #
  #  will be determined by the current session ID.                                                     #
  #                                                                                                    #
  #  "Current Session ID" will always be taken to refer to the present session frame.                  #
  #                                                                                                    #
  #  We need to store 4 things:                                                                        #
  #  * HMAC Verification Digest of session IDs in session                                              #
  #  * Encryption Key (secret)                                                                         #
  #  * Initialization Vector (secret)                                                                  #
  #  * encrypted session                                                                               #
  #                                                                                                    #
  #  Locally we store:                                                                                 #
  #                                                                                                    #
  #     key:     top_most_session_id_encrypted-session_stack_hmac_digest                               #
  #     data:    [  unencrypted_id,                                                                    #
  #                 encryption_key,                                                                    #
  #                 initialization_vector,                                                             #
  #                 session_stack_hmac_digest ]                                                        #
  #                                                                                                    #
  #  For verification we check:                                                                        #
  #                                                                                                    #
  #     * decrypted session ID matches stored top-most session ID                                      #
  #     * session stack HMAC matches stored HMAC                                                       #
  #                                                                                                    #
  ######################################################################################################

  ############################################# Persistence #################################################

  # FIX - rpersistence must non-atomically persist any persist_by that is not declared atomic
  # this can be fixed in persist_by simply by checking if it is atomic and if it is not then setting it non-atomic
  persist_declared_by   :encrypted_session_id
  attr_non_atomic       :session_id, :session_stack, :session_stack_hmac_digest, 
                        :encryption_key, :encryption_initialization_vector,
                        :domain, :path, :expire_after, :options
  # FIX - implement attr_flat
  attr_flat             :session_stack, :options
  
  attr_reader           :options
  attr_writer           :encrypted_session_id

  ############################################## Constants ##################################################

  SessionKey                     = 'rmagnets.session'.freeze
  
  # cipher values and digest type taken from Phusion's encrypted cookie store
  # https://github.com/FooBarWidget/encrypted_cookie_store
  InitializationVectorCipher    = 'aes-128-ecb'.freeze
  DataCipher                    = 'aes-256-cfb'.freeze
  
  DigestType                    = 'SHA1'.freeze
  
  SessionIDBits                 = 32  
  SessionIDRandModifier         = "%0#{ SessionIDBits / 4 }x".freeze
  SessionIDRandLimit            = ( 2**SessionIDBits ).freeze

  ########################################### Initialization ################################################

  ################
  #  initialize  #
  ################

  # application is any Rack-compatible app
  # options:
  # * :domain
  # * :path
  # * :expire_after
  def initialize( application, options = {} )

    @application                = application
    @options                    = options
    @cipher                     = OpenSSL::Digest.new( DataCipher )
    @iv_cipher                  = OpenSSL::Digest.new( InitializationVectorCipher )
    @session_stack              = Array.new

  end

  ####################################### Session Functionality #############################################

  ################
  #  session_id  #
  ################
  
  def session_id
    
    return @session_stack.last

  end
  
  ############
  #  domain  #
  ############

  def domain
    
    return options[ :domain ]

  end

  ##########
  #  path  #
  ##########

  def path
    
    return options[ :path ] ||  "/"

  end

  ##################
  #  expire_after  #
  ##################

  def expire_after
    
    return options[ :expire_after ]

  end

  ########################
  #  push_session_frame  #
  ########################
  
  # creates a new session state as current on top of previous state (can restore previous state by popping frame)
  def push_session_frame

    # cease persisting with old frame ID
    cease! if persistence_id

    # reset digest since our stack has changed
    @session_stack_hmac_digest = nil

    @session_stack.push( new_session_frame )

    # persist with new frame ID
    persist!( Rmagnets.session_storage_port, persistence_bucket, persistence_key )

    return self

  end

  #######################
  #  pop_session_frame  #
  #######################
  
  # restores session state from current to previous state
  def pop_session_frame
        
    # cease persisting by popped frame ID
    cease! if persistence_id

    # reset digest since our stack has changed
    @session_stack_hmac_digest = nil

    popped_frame = @session_stack.pop
    
    # persist with current ID if we still have one
    persist!( Rmagnets.session_storage_port, persistence_bucket, persistence_key ) unless @session_stack.empty?

    return popped_frame

  end

  ###########################
  #  reset_current_session  #
  ###########################

  # reset the current session state
  def reset_current_session

    pop_session_frame
    push_session_frame

  end
  
  #########################
  #  reset_session_stack  #
  #########################

  # reset all session frames
  def reset_session_stack

    # remove existing reference in persistence
    cease! if persistence_id

    @session_stack = Array.new
    push_session_frame

  end

end
