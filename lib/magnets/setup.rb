
::Magnets.extend( ::Magnets::Session::Rack )
::Magnets::Configuration.register_configuration( :session, ::Magnets::Session::Configuration )

class ::Hash
  include ::Persistence
end

class ::Array
  include ::Persistence
end
