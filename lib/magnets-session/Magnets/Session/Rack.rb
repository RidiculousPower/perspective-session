
module ::Magnets::Session::Rack

  attr_reader	:session
  
	#################
  #  application  #
  #################
  
	def application
	  
	  return @session ||= ::Magnets::Session.new( super )
		
  end

end
