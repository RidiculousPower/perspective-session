
#-----------------------------------------------------------------------------------------------------------#
#-----------------------------------------  Rmagnets Session  ----------------------------------------------#
#-----------------------------------------------------------------------------------------------------------#

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
  persists_declared_by  :encrypted_session_id
  attr_non_atomic       :session_id, :session_stack, :session_stack_hmac_digest, 
                        :encryption_key, :encryption_initialization_vector,
                        :domain, :path, :expire_after, :options

  attr_flat             :session_stack, :options
  
  attr_reader           :options
  attr_writer           :encrypted_session_id, :session_cookie

  ############################################## Constants ##################################################

  SessionKey                     = 'rmagnets.session'.freeze
  
  # cipher values and digest type taken from Phusion's encrypted cookie store
  # https://github.com/FooBarWidget/encrypted_cookie_store
  InitializationVectorCipher    = 'aes-128-ecb'.freeze
  DataCipher                    = 'aes-256-cfb'.freeze
  
  DigestType                    = 'SHA1'.freeze
  
  SessionIDBits                 = 128  
  SessionIDRandModifier         = "%0#{ SessionIDBits / 4 }x".freeze
  SessionIDRandLimit            = ( 2**SessionIDBits ).freeze
	
	CookieDelimiter								=	'--'

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
    @cipher                     = OpenSSL::Cipher.new( DataCipher )
    @iv_cipher                  = OpenSSL::Cipher.new( InitializationVectorCipher )
    @digest                     = OpenSSL::Digest::Digest.new( DigestType )
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

  #############
  #  domain=  #
  #############

  def domain=( domain )
    
    options[ :domain ] = domain

		return self
		
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

  ##################
  #  expire_after  #
  ##################

  def expire_after=( duration )
    
    options[ :expire_after ] = duration

		return self

  end

  ########################
  #  push_session_frame  #
  ########################
  
  # creates a new session state as current on top of previous state (can restore previous state by popping frame)
  def push_session_frame

    # cease persisting with old frame ID
    cease!( Rmagnets::Configuration::SessionStoragePort, persistence_bucket, persistence_key ) if persistence_id

    # reset digest and cookie since our stack has changed
		reset_session_stack_hmac_digest
		reset_session_cookie
		
		new_session_id = nil
    # make sure we don't have a collision for our new session id
    # if we do have a collision, recurse until we can return valid ID
		while self.class.persisted?( Rmagnets::Configuration::SessionStoragePort, persistence_bucket, encrypt_session_id( new_session_id = new_session_frame ) ) ;; end
    
    @session_stack.push( new_session_id )

    # persist with new frame ID
    persist!( Rmagnets::Configuration::SessionStoragePort, persistence_bucket, persistence_key )

    return self

  end

  #######################
  #  pop_session_frame  #
  #######################
  
  # restores session state from current to previous state
  def pop_session_frame
        
    # cease persisting by popped frame ID
    cease!( Rmagnets::Configuration::SessionStoragePort, persistence_bucket, persistence_key ) if persistence_id

    # reset digest since our stack has changed
		reset_session_stack_hmac_digest
		reset_session_cookie

    popped_frame = @session_stack.pop

		if @session_stack.empty?
    	reset_persistence_id_to( nil )
		else
			# persist with current ID if we still have one
	    persist!( Rmagnets::Configuration::SessionStoragePort, persistence_bucket, persistence_key )
		end
		
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
    cease!( Rmagnets::Configuration::SessionStoragePort, persistence_bucket, persistence_key ) if persistence_id

  	reset_persistence_id_to( nil )

    @session_stack = Array.new

    push_session_frame

  end

end
