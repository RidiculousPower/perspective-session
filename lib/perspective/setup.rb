
::Perspective.extend( ::Perspective::Session::Rack )
::Perspective::Configuration.register_configuration( :session, ::Perspective::Session::Configuration )

class ::Hash
  include ::Persistence
end

class ::Array
  include ::Persistence
end
