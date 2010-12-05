
describe Rmagnets::Session do

  $body_text   = 'Session ID: ' + session_id

  # simple rack adaptor app that returns a page with description of session ID as its body
  # this should let us test whether a session ID has been created and can be retrieved
  session_id_rack_application = lambda do |environment|
    session_id  = environment[ Rmagnets::Session::EnvironmentStorageKey ]
    Rack::Response.new( $body_text ).finish
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