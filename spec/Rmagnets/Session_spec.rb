require_relative '../../lib/rmagnets-session.rb'

# rmagnets development
require_relative '../../../lib/rmagnets.rb'

require_relative '../../lib/rmagnets-session/Rmagnets/Session.rb'
require_relative 'Session_rackapp.rb'
require_relative 'Rmagnets_config.rb'

describe Rmagnets::Session do

  ################
  #  initialize  #
  ################

  it "can be created with an application and standard session options" do
    session = Rmagnets::Session.new( $__rmagnets__spec__session_id_rack_application )
    session.should_not == nil
  end

  ############
  #  domain  #
  ############

  it "can report the domain this session stack covers" do
    session = Rmagnets::Session.new( $__rmagnets__spec__session_id_rack_application )
    session.domain.should == nil
    session.domain = 'somedomain.com'
    session.domain.should == 'somedomain.com'
  end

  ##########
  #  path  #
  ##########

  it "can report the path this session stack covers" do
    session = Rmagnets::Session.new( $__rmagnets__spec__session_id_rack_application )
    session.path.should == '/'
  end

  ##################
  #  expire_after  #
  ##################

  it "can report the duration before this cookie expires" do
    session = Rmagnets::Session.new( $__rmagnets__spec__session_id_rack_application )
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
    session = Rmagnets::Session.new( $__rmagnets__spec__session_id_rack_application )
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