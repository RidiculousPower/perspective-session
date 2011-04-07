
#######################
#  Rmagnets::Session  #
#######################

class Rmagnets::Session

  #####################################################################################################################
  ###############################################  Private  ###########################################################
  #####################################################################################################################

  ######################################### Rack Compatibility ###############################################

  ##########
  #  call  #
  ##########

  # Rack::Sesssion compatibility:
  # * responds to #call( environment )
  # * returns [ status, headers, body ]
  def call( environment )

    load_session( environment )

    status, headers, body = @application.call( environment )

    commit_session( headers )

    # hand call to application with environment set to session
    return status, headers, body

  end

  private
  
  ############################################ Load/Commit ################################################

  ##################
  #  load_session  #
  ##################

  # * ensure at least one session ID exists; create session containing ID if none already exists
  def load_session( environment )
    
    # we have a session id if:
    encrypted_session_id = Rack::Request.new( environment ).cookies[ SessionKey ]
    
    # if we have a session cookie we need to verify its authenticity
    unless  encrypted_session_id_verifies

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
    cookie = Hash.new
    cookie[ :value ]    = session_cookie
    cookie[ :expires ]  = Time.now + expire_after if expire_after
    # FIX - where does headers come from? don't we need environment here somewhere?
    Rack::Utils.set_cookie_header!( headers, SessionKey, cookie.merge( @options ) )

    return true
    
  end

  ########################################### Create Session ################################################

  #######################
  #  new_session_frame  #
  #######################
  
  # * generates session ID, used to identify unique environment state
  def new_session_frame
    
    # create new ID
    new_session_id  = RandModifier % rand( RandLimit )
    
    # make sure we don't have a collision
    if self.class.persisted?( Rmagnets.session_storage_port, persistence_bucket, new_session_id )
      # if we do have a collision, recurse until we can return valid ID
      return new_session_frame
    end
    
    return new_session_id
    
  end

  ##########################
  #  encrypted_session_id  #
  ##########################

  def encrypted_session_id
    
    unless @encrypted_session_id
      
      # initialize encryption
      @cipher.encrypt
      @cipher.key      = encryption_key
      @cipher.iv       = encryption_initialization_vector

      # encrypt the session ID
      @encrypted_session_id = @cipher.update( session_id ) << @cipher.final
      
    end
    
    return @encrypted_session_id
    
  end
  
  ###############################
  #  session_stack_hmac_digest  #
  ###############################
  
  def session_stack_hmac_digest
    
    return @session_stack_hmac_digest ||= OpenSSL::HMAC.hexdigest( OpenSSL::Digest::Digest.new( DigestType ), encryption_key, @session_stack.pack( "m*" ) )
    
  end
  
  ####################
  #  session_cookie  #
  ####################

  def session_cookie
    
    return encrypted_session_id.to_s + '--' + session_stack_hmac_digest.to_s
    
  end

  ####################
  #  encryption_key  #
  ####################

  # create or persist initialization vector and return
  def encryption_key
        
    return  @encryption_key  ||= @cipher.random_key

  end

  ######################################
  #  encryption_initialization_vector  #
  ######################################

  # create or persist initialization vector and return
  def encryption_initialization_vector
        
    return  @encryption_initialization_vector  ||= @cipher.random_iv

  end

  ############################################ Verify Cookie ################################################
  
  ###################################
  #  encrypted_session_id_verifies  #
  ###################################

  # FIX - implement persist for instance (fill in ivars)
  # FIX - :session_id, :encrypted_session_id, :session_stack, :session_stack_digest, :encrypted_session_id
  def encrypted_session_id_verifies
    
    # we have encrypted_session_id--hmac_digest_of_session_stack
    # * split encrypted id and hmac digest
    # * check encrypted ID vs. stored ID
    # * check hmac vs. stored hmac
    
    verified = false
    
    # if we don't have a cookie at all, verification fails
    if encrypted_session_id

      # split cookie into encrypted session ID and hmac digest for session stack
      encrypted_session_id, passed_session_stack_hmac_digest = encrypted_session_id.split( '--' )
    
      # persist stored info into self and verify
      # if no information was stored, verification fails
      if  persist( Rmagnets.session_storage_port, persistence_bucket, encrypted_session_id )  and
          decrypt_session_id == session_id                                                    and
          passed_session_stack_hmac_digest == session_stack_digest
      
        verified = true
      
      end
    
    end
    
    return verified
    
  end

  ########################################
  #  decrypt_packed_session_from_cookie  #
  ########################################
  
  def decrypt_session_id
    
    @cipher.decrypt
    @cipher.key     = encryption_key
    @cipher.iv      = encryption_initialization_vector
    session_id      = @cipher.update( encrypted_session_id ) << @cipher.final
    
    return session_id
    
  end

end
