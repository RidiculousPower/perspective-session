require_relative '../../../lib/rmagnets-session.rb'

# simple rack adaptor app that returns a page with description of session ID as its body
# this should let us test whether a session ID has been created and can be retrieved
session_id_rack_application = lambda do |environment|
  session_id  = environment[ Rmagnets::Session::SessionKey ]
  $body_text   = 'Session ID: ' + session_id
  Rack::Response.new( $body_text ).finish
end

describe Rmagnets::Session do

  #######################
  #  new_session_frame  #
  #######################
  
  it "can create a new session frame" do
    session = Rmagnets::Session.new( session_id_rack_application )
    class << session
      new_session_frame.to_s.length.should == 32
    end
  end

  ##########################
  #  encrypted_session_id  #
  ##########################

  it "" do
    pending
  end
  
  ###############################
  #  session_stack_hmac_digest  #
  ###############################
  
  it "" do
    pending
  end
  
  ####################
  #  session_cookie  #
  ####################

  it "" do
    pending
  end

  ####################
  #  encryption_key  #
  ####################

  it "" do
    pending
  end

  ######################################
  #  encryption_initialization_vector  #
  ######################################

  it "" do
    pending
  end
  
  ###################################
  #  encrypted_session_id_verifies  #
  ###################################

  it "" do
    pending
  end

  ########################################
  #  decrypt_packed_session_from_cookie  #
  ########################################

  it "" do
    pending
  end

  ##########
  #  call  #
  ##########

  it "" do
    pending
  end

  ##################
  #  load_session  #
  ##################

  it "" do
    pending
  end

  ####################
  #  commit_session  #
  ####################

  it "" do
    pending
  end

end