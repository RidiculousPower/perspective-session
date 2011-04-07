require_relative '../../lib/rmagnets-session.rb'

# simple rack adaptor app that returns a page with description of session ID as its body
# this should let us test whether a session ID has been created and can be retrieved
session_id_rack_application = lambda do |environment|
  session_id  = environment[ Rmagnets::Session::SessionKey ]
  $body_text   = 'Session ID: ' + session_id
  Rack::Response.new( $body_text ).finish
end

describe Rmagnets::Session do

  ################
  #  initialize  #
  ################

  it "" do
    pending
  end

  ################
  #  session_id  #
  ################
  
  it "" do
    pending
  end
  
  ############
  #  domain  #
  ############

  it "" do
    pending
  end

  ##########
  #  path  #
  ##########

  it "" do
    pending
  end

  ##################
  #  expire_after  #
  ##################

  it "" do
    pending
  end

  ########################
  #  push_session_frame  #
  ########################
  
  it "" do
    pending
  end

  #######################
  #  pop_session_frame  #
  #######################
  
  it "" do
    pending
  end

  ###########################
  #  reset_current_session  #
  ###########################

  it "" do
    pending
  end
  
  #########################
  #  reset_session_stack  #
  #########################

  it "" do
    pending
  end

  #################
  #  get_session  #
  #  set_session  #
  #################
  
  it "can get and set the session" do
    result = Rack::MockRequest.new( Rmagnets::Session.new( session_id_rack_application ) ).get( "/" )
    result[ "Set-Cookie" ].include?( Rmagnets::Session::EnvironmentStorageKey ).should == true
    result.body.should == $body_text
  end
  
  
end