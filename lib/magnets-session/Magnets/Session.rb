
#--------------------------------------------------------------------------------------------------#
#------------------------------------  Rmagnets Session  ------------------------------------------#
#--------------------------------------------------------------------------------------------------#

#######################
#  Rmagnets::Session  #
#######################

class ::Rmagnets::Session

       #---------------------#
  #####|  Rmagnets::Session  |######################################################################
  #    #---------------------#                                                                     #
  #                                                                                                #
  #  The purpose of the session is to sustain state between requests.                              #
  #  State is stored in a storage port because the session is a bad location to store state.       #
  #  The session should therefore do the absolute minimum necessary to enable persistent           #
  #  references, while doing the maximum to protect the intended persistence of those references.  #
  #                                                                                                #
  #  Minimal requirements:                                                                         #
  #  * an ID                                                                                       #
  #  * cookie storage                                                                              #
  #  * encryption/decryption for cookie                                                            #
  #                                                                                                #
  #  We add to these requirements the ability to specify:                                          #
  #  * session domain                                                                              #
  #  * session path (most specific path takes precedence)                                          #
  #  * expiration                                                                                  #
  #  * overlapping sessions                                                                        #
  #                                                                                                #
  #  The only point that issues any complication is overlapping sessions.                          #
  #                                                                                                #
  #  Multiple, simultaneous, overlapping sessions can be simply accomplished by moving from a      #
  #  single session ID to an array of session ID "frames".                                         #
  #                                                                                                #
  #  The last frame in the array will be considered the current session ID, and session state      #
  #  will be determined by the current session ID.                                                 #
  #                                                                                                #
  #  "Current Session ID" will always be taken to refer to the present session frame.              #
  #                                                                                                #
  #  We need to store 4 things:                                                                    #
  #  * HMAC Verification Digest of session IDs in session                                          #
  #  * Encryption Key (secret)                                                                     #
  #  * Initialization Vector (secret)                                                              #
  #  * encrypted session                                                                           #
  #                                                                                                #
  #  Locally we store:                                                                             #
  #                                                                                                #
  #     key:     top_most_session_id_encrypted-session_stack_hmac_digest                           #
  #     data:    [  unencrypted_id,                                                                #
  #                 encryption_key,                                                                #
  #                 initialization_vector,                                                         #
  #                 session_stack_hmac_digest ]                                                    #
  #                                                                                                #
  #  For verification we check:                                                                    #
  #                                                                                                #
  #     * decrypted session ID matches stored top-most session ID                                  #
  #     * session stack HMAC matches stored HMAC                                                   #
  #                                                                                                #
  ##################################################################################################

  ######################################## Persistence #############################################
  
  include Persistence
  
  attr_non_atomic_accessor  :session_id, :session_stack, :session_stack_hmac_digest, 
                            :encryption_key, :encryption_initialization_vector,
                            :domain, :path, :expire_after, :options

  attr_flat                 :session_stack, :options

  attr_index                :encrypted_session_id
  
  attr_reader               :options
  attr_writer               :encrypted_session_id, :session_cookie
                            
  self.instance_persistence_port = ::Rmagnets::Configuration.session_storage_port

  ######################################### Constants ##############################################

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

  ###################################### Initialization ############################################

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
    @session_stack              = [ ]

  end

  ################################## Session Functionality #########################################

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
  
  # creates a new session state as current on top of previous state 
  # (can restore previous state by popping frame)
  def push_session_frame

    # cease persisting with old frame ID
    if persistence_id
      cease!
    end
    
    # reset digest and cookie since our stack has changed
		reset_session_stack_hmac_digest
		reset_session_cookie
		
		new_session_id = nil
    # make sure we don't have a collision for our new session id
		while self.class.persisted?( :encrypted_session_id, 
		                             encrypt_session_id( new_session_id = new_session_frame ) )
      
      # if we do have a collision, recurse until we can return valid ID
		  reset_encrypted_session_id

		end
    
    @session_stack.push( new_session_id )

    # persist with new frame ID
    persist!

    return self

  end

  #######################
  #  pop_session_frame  #
  #######################
  
  # restores session state from current to previous state
  def pop_session_frame
        
    # cease persisting by popped frame ID
    if persistence_id
      cease!
    end
    
    # reset digest since our stack has changed
		reset_session_stack_hmac_digest
		reset_session_cookie

    popped_frame = @session_stack.pop

		if @session_stack.empty?
    	self.persistence_id = nil
		else
			# persist with current ID if we still have one
	    persist!
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
    if persistence_id
      cease!
    end
    
  	self.persistence_id = nil

    @session_stack = [ ]

    push_session_frame

  end

  #################################### Rack Compatibility ##########################################

  ##########
  #  call  #
  ##########

  # Rack::Sesssion compatibility:
  # * responds to #call( environment )
  # * returns [ status, headers, body ]
  def call( environment )

		# store reference to session object (self) in environment
		environment[ SessionKey ] = self

		# check for existing session cookie and verify/load it
		# create new session id if no cookie exists
    load_session( environment )

		# call Rack application
    status, headers, body = @application.call( environment )

		# ensure that our cookie appears inside the environment
		commit_session( headers )
		
		# return Rack application output with cookie in amended headers
    return status, headers, body

  end

  ##################################################################################################
      private ######################################################################################
  ##################################################################################################
  
  ####################################### Load/Commit ##############################################

  ##################
  #  load_session  #
  ##################

  # * ensure at least one session ID exists; create session containing ID if none already exists
  def load_session( environment )
    
		unless session_cookie_exists_in_environment_and_verifies( environment )			
			# reset session
			reset_session
			# initialize first session ID
      push_session_frame
		end
		
    return true
    
  end

  ####################
  #  commit_session  #
  ####################
  
  # at the end of creating a cookie we encrypt it and store it in a cookie in the environment
  def commit_session( headers )
    
    # store in environment
    cookie = { }
    cookie[ :value ]    = session_cookie
    cookie[ :expires ]  = Time.now + expire_after if expire_after

    Rack::Utils.set_cookie_header!( headers, SessionKey, cookie.merge( @options ) )

    return true
    
  end

  ###################################### Create Session ############################################

  #######################
  #  new_session_frame  #
  #######################
  
  # * generates session ID, used to identify unique environment state
  def new_session_frame
    
    return SessionIDRandModifier % rand( SessionIDRandLimit )    

  end

  ################################# Encrypt/Decrypt Session ########################################

  ####################
  #  encryption_key  #
  ####################

  def encryption_key        

    return @encryption_key ||= @cipher.random_key

  end

  ######################################
  #  encryption_initialization_vector  #
  ######################################

  def encryption_initialization_vector

    return @encryption_initialization_vector ||= @cipher.random_iv

  end

  ########################
  #  encrypt_session_id  #
  ########################

	def encrypt_session_id( id_to_encrypt )
		
		# initialize encryption
    @cipher.encrypt
    @cipher.key      = encryption_key
    @cipher.iv       = encryption_initialization_vector
		
    # encrypt the session ID
    @encrypted_session_id = @cipher.update( id_to_encrypt ) << @cipher.final
    
		return @encrypted_session_id
		
	end

  ##########################
  #  encrypted_session_id  #
  ##########################

  def encrypted_session_id

    if session_id
		  @encrypted_session_id ||= encrypt_session_id( session_id )
		end

		return @encrypted_session_id

  end

  ########################
  #  decrypt_session_id  #
  ########################
  
  def decrypt_session_id( encrypted_id_to_decrypt )
    
    @cipher.decrypt
    @cipher.key     = encryption_key
    @cipher.iv      = encryption_initialization_vector

    session_id      = @cipher.update( encrypted_id_to_decrypt ) << @cipher.final
    
    return session_id
    
  end

  ################################# Encode/Decode Session ##########################################

  #############################################
  #  base64_encoded_and_encrypted_session_id  #
  #############################################

  def base64_encoded_and_encrypted_session_id

    if session_id
		  @base64_encoded_and_encrypted_session_id ||= Base64.encode64( encrypted_session_id )
		end
		
		return @base64_encoded_and_encrypted_session_id

  end

  ########################################## Reset #################################################

  ###################
  #  reset_session  #
  ###################

	def reset_session
		
		reset_session_stack
		reset_session_cookie
		reset_session_stack_hmac_digest
		reset_encryption_key
		reset_encryption_initialization_vector
		
		return self
		
	end

  ##########################
  #  reset_session_cookie  #
  ##########################
  
  def reset_session_cookie
    
		@session_cookie = nil
  
  end

  #####################################
  #  reset_session_stack_hmac_digest  #
  #####################################
  
  def reset_session_stack_hmac_digest
	
		@session_stack_hmac_digest = nil
  
  end

  ##########################
  #  reset_encryption_key  #
  ##########################
  
  def reset_encryption_key
	
		@encryption_key = nil
  
  end

  ################################
  #  reset_encrypted_session_id  #
  ################################
  
  def reset_encrypted_session_id
	
		@encrypted_session_id = nil
  
  end

  ############################################
  #  reset_encryption_initialization_vector  #
  ############################################
  
  def reset_encryption_initialization_vector
	
		@encryption_initialization_vector = nil
  
  end

  ######################################### Cookie #################################################

  ###############################
  #  session_stack_hmac_digest  #
  ###############################
  
  def session_stack_hmac_digest
  
    return @session_stack_hmac_digest ||= OpenSSL::HMAC.digest( @digest, 
                                                                encryption_key, 
                                                                @session_stack.pack( "m*" ) )    
  
  end

  ##############################################
  #  base64_encoded_session_stack_hmac_digest  #
  ##############################################
  
  def base64_encoded_session_stack_hmac_digest
  
    return Base64.encode64( session_stack_hmac_digest )
  
  end
  
  ####################
  #  session_cookie  #
  ####################

  def session_cookie
    
    return @session_cookie ||= base64_encoded_and_encrypted_session_id  + 
                               CookieDelimiter                          + 
                               base64_encoded_session_stack_hmac_digest
    
  end

  ####################################### Verify Cookie ############################################

  #######################################################
  #  session_cookie_exists_in_environment_and_verifies  #
  #######################################################

	def session_cookie_exists_in_environment_and_verifies( environment )

		session_cookie_exists_in_environment_and_verifies	=	false

    # we have a session id if we have a stored cookie by our session key
    stored_session_cookie = Rack::Request.new( environment ).cookies[ SessionKey ]

		# if we have a stored cookie
		if 	stored_session_cookie

			# we split our cookie into its two parts
			# * the first part is our base64 encoded encrypted session ID
			# * the second part is our base64 packed session stack hmac digest
			# Both parts are base64 encoded immediately before being put into the cookie.
			stored_session_cookie_parts 			= stored_session_cookie.split( CookieDelimiter )
			stored_encrypted_session_id 			= Base64.decode64( stored_session_cookie_parts[ 0 ] )
			stored_session_stack_hmac_digest 	= Base64.decode64( stored_session_cookie_parts[ 1 ] )

			# and we can persist the rest of our configuration using the encrypted ID from the cookie
    	if persist
			
				# and we can verify the cookie combination of encrypted current session ID 
				# and session stack hmac digest
				if encrypted_session_id_verifies( stored_encrypted_session_id, 
				                                  stored_session_stack_hmac_digest )

					session_cookie_exists_in_environment_and_verifies	=	true
				
				end

			end

		end		
		
		return session_cookie_exists_in_environment_and_verifies

	end
  
  ###################################
  #  encrypted_session_id_verifies  #
  ###################################

  def encrypted_session_id_verifies( cookie_encrypted_session_id, cookie_session_stack_hmac_digest )

    # we have encrypted_session_id--hmac_digest_of_session_stack
    # * split encrypted id and hmac digest
    # * check encrypted ID vs. stored ID
    # * check hmac vs. stored hmac
    
    verified = false
    
    # persist stored info into self and verify
    # if no information was stored, verification fails
    if  decrypt_session_id( cookie_encrypted_session_id ) == session_id		and
        cookie_session_stack_hmac_digest == session_stack_hmac_digest
    
      verified = true
    
    end
    
    return verified
    
  end

end
