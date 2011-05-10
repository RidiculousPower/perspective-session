
#-----------------------------------------------------------------------------------------------------------#
#--------------------------------------  Rmagnets Configuration  -------------------------------------------#
#-----------------------------------------------------------------------------------------------------------#

require_relative '/Users/asher/Projects/rp/rpersistence/adapters/yaml/flat-file/lib/rpersistence-adapter-yaml-flat-file'

module Rmagnets::Configuration
	
	# SessionStoragePort	-	where session frames will persist
	SessionStoragePort	=	Rpersistence::Port.new( :session_storage_port, Rpersistence::Adapter::YamlFlatFile.new( '/tmp/rmagnets-session-magnets-yaml-flat-file' ) )
	
end
