require 'rack/request'
require 'rack/response'

# session id cookie is stored with base64 encoding
require 'base64'

# once decoded from base64, session id is encrypted
require 'openssl'

# encryption key is kept in persistence layer
require 'rpersistence'

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
  #  * Initialization Vector                                                                           #
  #  * encrypted session                                                                               #
  #                                                                                                    #
  #  We HMAC then encrypt, so we store HMAC Digest, Encryption Key, and Initialization Vector locally  #
  #  then we issue the encrypted session in a cookie (base64 encoded prior to HMAC digest creation).   #
  #                                                                                                    #
  #  Locally we store top-most session ID => {  encrypted_id,                                          #
  #                                             encryption_key,                                        #
  #                                             initialization_vector,                                 #
  #                                             hmac_digest }.                                         #
  #                                                                                                    #
  ######################################################################################################

  persist_declared_by   :id
  atomic_writer         :encrypted_id, :initialization_vector, :hmac_digest 

  KeyInEnvironment              = 'rack.session'.freeze
  # cipher values and digest type taken from Phusion's encrypted cookie store
  # https://github.com/FooBarWidget/encrypted_cookie_store
  InitializationVectorCipher    = 'aes-128-ecb'.freeze
  DataCipher                    = 'aes-256-cfb'.freeze
  DigestType                    = 'SHA1'.freeze

  ################
  #  initialize  #
  ################

  def initialize( application, options = {} )
    @application                = application
    @options                    = options
    @domain                     = options[ :domain ]
    @path                       = options[ :path ]          ||  "/"
    @expire_after               = options[ :expire_after ]
    @cipher                     = OpenSSL::Cipher::Cipher.new( DataCipher )
    @iv_cipher                  = OpenSSL::Cipher::Cipher.new( InitializationVectorCipher )
    @session_frames             = [ ]
  end

  ##########
  #  call  #
  ##########

  # a Rack::Session compatible class functions as a wrapper for a Rack adapter (the application)
  # this means nothing more than it is itself a Rack adapter that calls the application
  def call( environment )
    ensure_session_id_exists( environment )
    status, headers, body = @application.call( environment )
    ensure_session_persists( environment, status, headers, body )
    return status, headers, body
  end

  ########
  #  id  #
  ########
  
  def id
    return @session_frames.last
  end

  ################
  #  push_frame  #
  ################
  
  # creates a new session state as current on top of previous state (can restore previous state by popping frame)
  def push_frame
    @session_frames.push( new_session_frame )
    return self
  end

  ###############
  #  pop_frame  #
  ###############
  
  # restores session state from current to previous state
  def pop_frame
    popped_frame = @session_frames.pop
    # popping last frame is equivalent to starting with a fresh session stack
    push_frame if @session_frames.empty?
    return popped_frame
  end
  
  ###################
  #  reset_session  #
  ###################

  # reset the current session state
  def reset_session
    pop_frame
    push_frame
  end
  
  #####################################################################################################################
  ###############################################  Private  ###########################################################
  #####################################################################################################################

  ##############################
  #  ensure_session_id_exists  #
  ##############################

  # * ensure at least one session ID exists; create session containing ID if none already exists
  def ensure_session_id_exists( environment )
    session_cookie_exists_in_request( environment )     and 
      decrypt_packed_session_from_cookie                and
      verify_session                                    and
      unpack_session                              or
    push_frame                                          and
      pack_session                                      and
      digest_session                                    and
      encrypt_packed_session_and_store_in_cookie( environment )
  end

  #############################
  #  ensure_session_persists  #
  #############################
  
  # ensure_session_persists is responsible for:
  # * ensuring a session ID encryption key exists
  # * ensuring session ID is encrypted and stored in environment cookies
  def ensure_session_persists( environment, status, headers, body )
    cookie = Hash.new
    cookie[ :value ]    = generate_encrypted_id
    cookie[ :expires ]  = Time.now + @expire_after if @expire_after
    Rack::Utils.set_cookie_header!( headers, KeyInEnvironment, cookie.merge( @options ) )
  end

  #####################################################################################################################

  ######################################
  #  session_cookie_exists_in_request  #
  ######################################
  
  def session_cookie_exists_in_request( environment )
    @encrypted_packed_session_array ||= Rack::Request.new( environment ).cookies[ @environment_storage_key ]
  end
  
  ########################################
  #  decrypt_packed_session_from_cookie  #
  ########################################
  
  def decrypt_packed_session_from_cookie
    @cipher.decrypt
    @cipher.key  = encryption_key
    @cipher.iv   = encryption_initialization_vector
    @packed_session_array  = @cipher.update( @session ) << @cipher.final
  end

  ####################
  #  verify_session  #
  ####################
  
  def verify_session
    
  end

  ####################
  #  unpack_session  #
  ####################
  
  def unpack_session
    @session = @packed_session_array.unpack( "m*" )
  end

  ####################
  #  session_digest  #
  ####################
  
  def session_digest
    
  end
  
  #####################################################################################################################

  #######################
  #  new_session_frame  #
  #######################
  
  # * generates session ID, used to identify unique environment state
  def new_session_frame
    return "%0#{ SessionIDBits / 4 }x" % rand( 2**SessionIDBits )
  end

  ##################
  #  pack_session  #
  ##################
  
  def pack_session
    @packed_session_array = @session.pack( "m*" )
  end

  ####################
  #  digest_session  #
  ####################
  
  def digest_session
    OpenSSL::HMAC.hexdigest( OpenSSL::Digest::Digest.new( DigestType ), encryption_key, data )
  end
  
  ################################################
  #  encrypt_packed_session_and_store_in_cookie  #
  ################################################
  
  def encrypt_packed_session_and_store_in_cookie( environment )
    @cipher.encrypt
    @cipher.key  = encryption_key
    @cipher.iv   = encryption_initialization_vector
    @encrypted_packed_session_array  = @cipher.update( @id ) << @cipher.final
  end

  ####################
  #  encryption_key  #
  ####################

  def encryption_key
    # get session key from persistence storage port or create if necessary
    unless session_id_encryption_key = Rmagnets::Session::Key.persist( Rmagnets.session_storage_port, @id, @environment_storage_key, @domain, @path, @cipher.random_iv )
      # create session key and persist storage key in storage port if not already existing
      session_id_encryption_key = Rmagnets::Session::Frame.new( @id, @environment_storage_key, @domain, @path, @cipher.random_iv ).persist!( Rmagnets.session_storage_port ).encryption_key
    end
    return session_id_encryption_key  
  end

  ######################################
  #  encryption_initialization_vector  #
  ######################################

  def encryption_initialization_vector
    return  Rmagnets::Session::InitializationVector.persist( Rmagnets.session_storage_port, @id ) || 
            Rmagnets::Session::InitializationVector.new( @id, @cipher.random_iv ).persist!( Rmagnets.session_storage_port )
  end
  
end
