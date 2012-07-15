
module ::Magnets::Session::Configuration

	##################
	#  storage_port  #
	##################
	
	def storage_port
	  
	  return @storage_port || ::Persistence.current_port
	  
  end

	###################
	#  storage_port=  #
	###################
	
	def storage_port=( session_storage_port )
	  
	  @storage_port = session_storage_port
	  
  end
  
end
