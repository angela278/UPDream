"""`appengine_config` gets loaded when starting a new application instance."""
import sys
import os.path
import os
# add `lib` subdirectory to `sys.path`, so our `main` module can load
# third-party libraries.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

if os.environ.get('SERVER_SOFTWARE', '').startswith('Development'): 
	import imp 
	import os.path 
	from google.appengine.tools.devappserver2.python import sandbox 

	sandbox._WHITE_LIST_C_MODULES += ['_ssl', '_socket'] 
	# Use the system socket. 
	psocket = os.path.join(os.path.dirname(os.__file__), 'socket.py') 
	imp.load_source('socket', psocket)