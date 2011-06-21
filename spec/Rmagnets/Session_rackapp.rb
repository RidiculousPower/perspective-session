
# simple rack adaptor app that returns a page with description of session ID as its body
# this should let us test whether a session ID has been created and can be retrieved
$__rmagnets__spec__session_id_rack_application = lambda do |environment|

	# get request from environment 
	request = Rack::Request.new( environment )

	# create body text, store in global so we can compare result
  $__rmagnets__spec__body_text   = 'Session ID: ' + environment[ Rmagnets::Session::SessionKey ].session_id.to_s

	# generate and return header, body, status
  return Rack::Response.new(	$__rmagnets__spec__body_text, 
															request.GET[ 'status' ] || 200, 
															'Content-Type' => 'text/html' ).finish

end
