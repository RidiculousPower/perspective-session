require_relative '../../../lib/rmagnets-session.rb'

require_relative '../Session_rack.rb'
require_relative '../Rmagnets_config.rb'

require 'rack'

describe Rmagnets::Session do

  #######################
  #  new_session_frame  #
  #######################
  
  it "can create a new session frame" do
    session = Rmagnets::Session.new( $__rmagnets__spec__session_id_rack_application )
    session.instance_eval do
      new_session_frame.to_s.length.should == 32
    end
  end

  ##########################
  #  encrypted_session_id  #
  ##########################

  it "can return an encrypted version of the session ID" do
    session = Rmagnets::Session.new( $__rmagnets__spec__session_id_rack_application )
    session.instance_eval do
      session_stack = instance_variable_get( :@session_stack )
      session_stack.push( new_session_frame )
      encrypted_session_id.should_not == nil
    end    
  end

  ########################
  #  encrypt_session_id  #
  ########################

  it "can encrypt a session ID" do
    session = Rmagnets::Session.new( $__rmagnets__spec__session_id_rack_application )
    session.instance_eval do
      session_stack = instance_variable_get( :@session_stack )
      session_stack.push( new_session_frame )
      encrypted_id = encrypt_session_id( session_id )
      encrypted_id.should_not == nil
      decrypt_session_id( encrypted_id ).should == session_id
    end    
  end
  
  ###############################
  #  session_stack_hmac_digest  #
  ###############################
  
  it "can return an hmac digest of the session stack" do
    session = Rmagnets::Session.new( $__rmagnets__spec__session_id_rack_application )
    session.instance_eval do
      session_stack = instance_variable_get( :@session_stack )
      session_stack.push( new_session_frame )
      session_stack_hmac_digest.should_not == nil
    end    
  end
  
  ####################
  #  session_cookie  #
  ####################

  it "can return the current session information in cookie form" do
    session = Rmagnets::Session.new( $__rmagnets__spec__session_id_rack_application )
    session.instance_eval do
      session_stack = instance_variable_get( :@session_stack )
      session_stack.push( new_session_frame )
      session_cookie.should == base64_encoded_and_encrypted_session_id + '--' + base64_encoded_session_stack_hmac_digest
    end
  end

  ####################
  #  encryption_key  #
  ####################

  it "has an encryption key" do
    session = Rmagnets::Session.new( $__rmagnets__spec__session_id_rack_application )
    session.instance_eval do
      encryption_key.should_not == nil
    end    
  end

  ######################################
  #  encryption_initialization_vector  #
  ######################################

  it "has an initialization vector" do
    session = Rmagnets::Session.new( $__rmagnets__spec__session_id_rack_application )
    session.instance_eval do
      encryption_initialization_vector.should_not == nil
    end    
  end
  
  ###################################
  #  encrypted_session_id_verifies  #
  ###################################

  it "can verify the encrypted session ID" do
    session = Rmagnets::Session.new( $__rmagnets__spec__session_id_rack_application )
    session.instance_eval do
      session_stack = instance_variable_get( :@session_stack )
      session_stack.push( new_session_frame )
      encrypted_session_id_verifies( encrypted_session_id, session_stack_hmac_digest ).should == true
    end    
  end

  ####################
  #  call            #
  #  commit_session  #
  #  load_session    #
  ####################
  
  it "is intended to function as Rack middleware" do
    
    # create a session instance that uses our spec app
    session = Rmagnets::Session.new( $__rmagnets__spec__session_id_rack_application )
    # get a mock result from our session app
    first_result = Rack::MockRequest.new( session ).get( '' )
    # verify cookie results from request
    first_result[ 'Set-Cookie' ].slice( 0, Rmagnets::Session::SessionKey.length ).should == Rmagnets::Session::SessionKey
    # ensure that resulting cookie decrypts and verifies
    first_decrypted_id = verify_session_cookie( session, first_result )
    
    cookie = first_result[ 'Set-Cookie' ]
    second_result = Rack::MockRequest.new( session ).get( '', 'HTTP_COOKIE' => cookie )
    second_decrypted_id = verify_session_cookie( session, second_result )
    second_decrypted_id.should == first_decrypted_id

  end

  def verify_session_cookie( session, mock_result )
    
    decrypted_id = nil
    
    session.instance_eval do
      # we need to check cookies by way of our header
      # only have one cookie so this is not difficult -
      # * first, get rid of our cookie name
      cookie_session_cookie = mock_result[ 'Set-Cookie' ].split( '=' )[1]
      # * second, unescape any encoded text
      unescaped_cookie_session_cookie = Rack::Utils.unescape( cookie_session_cookie )
      # split the cookie into its two parts we need to test
      cookie_base64_encoded_encrypted_session_id, cookie_session_stack_hmac_digest = unescaped_cookie_session_cookie.split( Rmagnets::Session::CookieDelimiter )
      # verify base64 encoded first part (base 64 encoded encrypted session)
      cookie_base64_encoded_encrypted_session_id.should == base64_encoded_and_encrypted_session_id
      # base64 decode the first part (the encrypted session)
      encrypted_id = Base64.decode64( cookie_base64_encoded_encrypted_session_id )
      # verify encrypted session ID
      encrypted_id.should == encrypted_session_id
      # decrypt and verify session ID
      decrypted_id = decrypt_session_id( encrypted_id )
      decrypted_id.should == session.session_id
    end
    
    return decrypted_id
    
  end

end