
module ::Perspective::Session::Rack

  attr_reader	:session
  
	#################
  #  application  #
  #################
  
	def application
	  
	  return @session ||= ::Perspective::Session.new( super )
		
  end

end
