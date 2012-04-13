
require 'persistence-adapter-mock'
require 'rack'
$__magnets__spec__development_ = true
if $__magnets__spec__development_
  require_relative '../../lib/magnets-session.rb'
  require_relative '../../../lib/magnets.rb'
else
  require 'magnets-session'
  require 'magnets'
end

require_relative 'Session_rackapp.rb'

describe ::Magnets::Session do

  before :all do
    Persistence.enable_port( :mock, Persistence::Adapter::Mock.new )
  end
  
  after :all do
    Persistence.disable_port( :mock )
  end

  ######################################### Private ################################################

  #######################
  #  new_session_frame  #
  #######################
  
  it "can create a new session frame" do
    session = ::Magnets::Session.new( $__magnets__spec__session_id_rack_application )
    session.instance_eval do
      new_session_frame.to_s.length.should == 32
    end
  end

  ##########################
  #  encrypted_session_id  #
  ##########################

  it "can return an encrypted version of the session ID" do
    session = ::Magnets::Session.new( $__magnets__spec__session_id_rack_application )
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
    session = ::Magnets::Session.new( $__magnets__spec__session_id_rack_application )
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
    session = ::Magnets::Session.new( $__magnets__spec__session_id_rack_application )
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
    session = ::Magnets::Session.new( $__magnets__spec__session_id_rack_application )
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
    session = ::Magnets::Session.new( $__magnets__spec__session_id_rack_application )
    session.instance_eval do
      encryption_key.should_not == nil
    end    
  end

  ######################################
  #  encryption_initialization_vector  #
  ######################################

  it "has an initialization vector" do
    session = ::Magnets::Session.new( $__magnets__spec__session_id_rack_application )
    session.instance_eval do
      encryption_initialization_vector.should_not == nil
    end    
  end
  
  ###################################
  #  encrypted_session_id_verifies  #
  ###################################

  it "can verify the encrypted session ID" do
    session = ::Magnets::Session.new( $__magnets__spec__session_id_rack_application )
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
    session = ::Magnets::Session.new( $__magnets__spec__session_id_rack_application )
    # get a mock result from our session app
    first_result = ::Rack::MockRequest.new( session ).get( 'http://somedomain.com/path/to/somewhere' )
    # verify cookie results from request
    first_result[ 'Set-Cookie' ].slice( 0, ::Magnets::Session::SessionKey.length ).should == ::Magnets::Session::SessionKey
    # ensure that resulting cookie decrypts and verifies
    first_decrypted_id = verify_session_cookie( session, first_result )
    
    cookie = first_result[ 'Set-Cookie' ]
    second_result = ::Rack::MockRequest.new( session ).get( '', 'HTTP_COOKIE' => cookie )
    second_decrypted_id = verify_session_cookie( session, second_result )
    second_decrypted_id.should == first_decrypted_id

  end

  ###########################
  #  verify_session_cookie  #
  ###########################

  def verify_session_cookie( session, mock_result )
    
    decrypted_id = nil
    
    session.instance_eval do
      # we need to check cookies by way of our header
      # only have one cookie so this is not difficult -
      # * first, get rid of our cookie name
      cookie_session_cookie = mock_result[ 'Set-Cookie' ].split( '=' )[1]
      # * second, unescape any encoded text
      unescaped_cookie_session_cookie = ::Rack::Utils.unescape( cookie_session_cookie )
      # split the cookie into its two parts we need to test
      cookie_base64_encoded_encrypted_session_id, cookie_session_stack_hmac_digest = unescaped_cookie_session_cookie.split( ::Magnets::Session::CookieDelimiter )
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

  ########################################## Public ################################################

  ################
  #  initialize  #
  ################

  it "can be created with an application and standard session options" do
    session = ::Magnets::Session.new( $__magnets__spec__session_id_rack_application )
    session.should_not == nil
  end

  ############
  #  domain  #
  ############

  it "can report the domain this session stack covers" do
    session = ::Magnets::Session.new( $__magnets__spec__session_id_rack_application )
    session.domain.should == nil
    session.domain = 'somedomain.com'
    session.domain.should == 'somedomain.com'
  end

  ##########
  #  path  #
  ##########

  it "can report the path this session stack covers" do
    session = ::Magnets::Session.new( $__magnets__spec__session_id_rack_application )
    session.path.should == '/'
  end

  ##################
  #  expire_after  #
  ##################

  it "can report the duration before this cookie expires" do
    session = ::Magnets::Session.new( $__magnets__spec__session_id_rack_application )
    session.expire_after.should == nil
    session.expire_after = 420
    session.expire_after.should == 420
  end

  ###########################
  #  push_session_frame     #
  #  session_id             #
  #  pop_session_frame      #
  #  reset_current_session  #
  #  reset_session_stack    #
  ###########################
  
  it "can report the session ID, push and pop session frames, and reset the current session or session stack" do
    session = ::Magnets::Session.new( $__magnets__spec__session_id_rack_application )
    session.session_id.should == nil
    # first session id
    session.push_session_frame
    session.session_id.should_not == nil
    # get rid of it
    session.pop_session_frame
    session.session_id.should == nil
    # new frame
    session.push_session_frame
    first_session_id = session.session_id
    # reset the current frame
    session.reset_current_session
    session.session_id.should_not == nil
    session.session_id.should_not == first_session_id
    second_session_id = session.session_id
    # stack on a new session id
    session.push_session_frame
    session.session_id.should_not == second_session_id
    # reset the whole stack
    session.reset_session_stack
    session.session_id.should_not == nil
    session.session_id.should_not == first_session_id
    session.session_id.should_not == second_session_id
  end

end