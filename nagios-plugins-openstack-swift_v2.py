#!/bin/python

## Copyright (c) 2015:
## The Italian Natinal Institute of Nuclear Physics (INFN), Italy

## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.

## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
## http://www.apache.org/licenses/LICENSE-2.0

## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.

import os, sys, datetime, re, uuid, signal
import logging, logging.handlers
import requests, json, socket

import swiftclient.client as swclient
import swiftclient.exceptions as swclientexceptions
import keystoneclient.v2_0.client as ksclient

from OpenSSL.SSL import TLSv1_METHOD
from OpenSSL.SSL import Context, Connection
from OpenSSL.SSL import VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT
from OpenSSL.SSL import Error as SSLError

from urlparse import urlparse
from optparse import OptionParser

"""
nagios-plugins-openstack-swift_v2.py

This is a new NAGIOS probe for testing some OpenStack SWIFT functionalities.
The new probe performs the following operations:
- Creates a new swift container;
- Create a new swift object file;
- Download the content of the object file locally;
- Delete the swift object file;
- Delete the swift container.
"""

__author__    = "Giuseppe LA ROCCA"
__email__     = "giuseppe.larocca@ct.infn.it"
__version__   = "$Revision: 0.0.4 $"
__date__      = "$Date: 23/11/2015 15:29:19 $"
__copyright__ = "Copyright (c) 2015 INFN"
__license__   = "Apache Licence v2.0"

def errmsg_from_excp(e):

        if getattr(e, 'message', False):
                retstr = ''
                if isinstance(e.message, list) \
                        or isinstance(e.message, tuple) \
                        or isinstance(e.message, dict):
                                for s in e.message:
                                        if isinstance(s, str):
                                                retstr += s + ' '
                                        if isinstance(s, tuple) or isinstance(s, tuple):
                                                retstr += ' '.join(s)
                                return retstr
                elif isinstance(e.message, str):
                        return e.message

                else:
                        for s in e.message:
                                retstr += str(s) + ' '
                        return retstr
        else:
                return str(e)

def nagios_out(status, msg, retcode):
	"Print NAGIOS messages"

        sys.stdout.write(status+": "+msg+"\n")
        sys.exit(retcode)

def server_ok(serverarg, capath, timeout):
        "Check if the server is active and responsive"

        server_ctx = Context(TLSv1_METHOD)
        server_ctx.load_verify_locations(None, capath)

        def verify_cb(conn, cert, errnum, depth, ok):
                return ok

        server_ctx.set_verify(VERIFY_PEER|VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb)

        serverarg = re.split("/*", serverarg)[1]
        if ':' in serverarg:
                serverarg = serverarg.split(':')
                server = serverarg[0]
                port = int(serverarg[1] if not '?' in serverarg[1] else serverarg[1].split('?')[0])
        else:
                server = serverarg
                port = DEFAULT_PORT

        try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((server, port))

                server_conn = Connection(server_ctx, sock)
                server_conn.set_connect_state()

                try:
                        def handler(signum, frame):
                                raise socket.error([('Timeout', 'after', str(timeout) + 's')])

                        signal.signal(signal.SIGALRM, handler)
                        signal.alarm(timeout)
                        server_conn.do_handshake()
                        signal.alarm(0)

                except socket.timeout as e:
                        nagios_out('Critical', 
			'Connection error %s - %s' % (server + ':' + str(port), errmsg_from_excp(e)),2)
                server_conn.shutdown()
                server_conn.close()

        except (SSLError, socket.error) as e:
                if 'sslv3 alert handshake failure' in errmsg_from_excp(e):
                        pass
                else:
                        nagios_out('Critical', 
			'Connection error %s - %s' % (server + ':' + str(port), errmsg_from_excp(e)), 2)

        return True

def main():

	parser = OptionParser()
        parser.add_option(
                '--endpoint', dest="endpoint",
                help="The Keystone public endpoint",
                metavar="string")
        parser.add_option(
                '--cert', dest="proxy",
                help="The X.509 proxy certificate",
                metavar="filename")
        parser.add_option(
                '--capath', dest="capath",
                help="The location of trusted cert dir",
                metavar="directory")
        parser.add_option(
                '--auth', dest="auth",
                help="The Auth version. Default value is '2.0'",
                metavar="double")
        parser.add_option(
                '--retries', dest="retries",
                help="Number of times to retry the request before failing. Default is '5'",
                metavar="integer")
	parser.add_option(
                '-t', '--timeout', dest="timeout",
                help="The MAX. timeout (in sec.) before to exit. Default is '120'",
                metavar="integer")
        parser.add_option(
                '--stdout-file', dest="std",
                help="The standart output where redirect the cron",
                metavar="filename")
	parser.add_option(
		'-v', '--verbose', dest="verbose",
                action="store_true", default=False)

        (options, args) = parser.parse_args()

        if (((options.endpoint) == None) | ((options.proxy) == None)):
                # stop the program and print an error message
                print """
Usage: nagios-plugins-openstack-swift_v2.py [OPTIONS]

OPTIONS:
 -h, --help            
	Show this help message and exit
          
 --endpoint=string
	The Keystone public endpoint
 
 --cert=filename
	The X.509 proxy certificate
 
 --capath=directory
	The location of trusterd cert dir. Default is '/etc/grid-security/certificates'

 --auth=double
 	The Auth version. Default value is '2.0'

 --retries=integer
 	Number of times to retry the request before failing. Default is '5'

 -t, --timeout=integer
	The MAX. timeout (in sec.) before to exit. Default is '120'

 --stdout-file=filename
        The standart output where redirect the cron
 
 -v, --verbose
	Default is False
"""
	else:
                # Redirecting stdout/stderr files       
                if (os.path.exists(options.std)):
                       sys.stdout = open(options.std, 'a')
                       sys.stderr = open(options.std, 'a')
                else:
                       sys.stdout = open(options.std, 'w')
                       sys.stderr = open(options.std, 'w')

                # Set up a specific logger with our desired output level
                logger = logging.getLogger('logger')
                logger.setLevel(logging.DEBUG)

                # Add the log message handler to the logger
                handler = logging.handlers.RotatingFileHandler(options.std, backupCount=50)
                logger.addHandler(handler)

                if ((options.capath) == None):
                        options.capath='/etc/grid-security/certificates/'

                if ((options.auth) == None):
                        options.auth='2.0'

                if ((options.retries) == None):
                        options.retries='5'

                if ((options.timeout) == None):
                        options.timeout='120'
                
		endpoint = options.endpoint
		cert = options.proxy
		capath = options.capath
		timeout = options.timeout
		verbose = options.verbose
		
		if (verbose):
		        logger.debug ("[ Using Settings ]")
        		logger.debug ("Verbose 	  = %s " % verbose)
        		logger.debug ("Server endpoint   = %s " % endpoint)
                	logger.debug ("X.509 proxy 	  = %s " % cert)
		        logger.debug ("Trusted CA path   = %s " % capath)
        		logger.debug ("Timeout (in sec.) = %s " % timeout)

		if (verbose):
	        	logger.debug ("\n- Checking the server status")
		server_status = server_ok(endpoint, capath, int(timeout))

		if (server_status):
			if (verbose):
	                	logger.debug ("- The server status is [ OK ]")
			o = urlparse(endpoint)

			try:
				# fetch unscoped token
				token_suffix = ''
				if o.netloc.endswith("v2.0"):
					token_suffix = token_suffix+'/tokens'
				else:
					token_suffix = token_suffix+'/v2.0/tokens'

				headers, payload, token = {}, {}, None
				headers.update({'Accept': '*/*'})
				headers = {'content-type': 'application/json', 'accept': 'application/json'}
				payload = {'auth': {'voms': True}}

				response = requests.post(
						o.scheme+'://'+o.netloc+token_suffix, 
						headers=headers,
						data=json.dumps(payload), 
						cert=cert, 
						verify=False, 
						timeout=int(timeout))
	                
				response.raise_for_status()
				token = response.json()['access']['token']['id']

			except (KeyError, IndexError) as e:
				nagios_out('Critical', 
				'Could not fetch unscoped keystone token from response: Key not found %s' 
				% errmsg_from_excp(e), 2)

			except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
				nagios_out('Critical', 
				'Connection error %s - %s' % (o.scheme+'://'+o.netloc+tenant_suffix, errmsg_from_excp(e)), 2)

			try:
				# use unscoped token to get a list of allowed tenants mapped to
				# fedcloud.egi.eu VO from VOMS proxy cert
				tenant_suffix= ''
				if o.netloc.endswith("v2.0"):
					tenant_suffix = tenant_suffix+'/tenants'
				else:
					tenant_suffix = tenant_suffix+'/v2.0/tenants'
			
				headers = {'content-type': 'application/json', 'accept': 'application/json'}
				headers.update({'x-auth-token': token})
				response = requests.get(
					o.scheme+'://'+o.netloc+tenant_suffix, 
					headers=headers,
					data=None, 
					cert=cert, 
					verify=False, 
					timeout=int(timeout))

				response.raise_for_status()
				
				tenants = response.json()['tenants']
				tenant = ''

				for t in tenants:
					if 'EGI_FCTF' in t['name']:	# <== Change it!
						tenant = t['name']
	                
			except (KeyError, IndexError) as e:
				nagios_out('Critical', 
				'Could not fetch allowed tenants from response: Key not found %s' 
				% errmsg_from_excp(e), 2)

			except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
				nagios_out('Critical', 
				'Connection error %s - %s' 
				% (o.scheme+'://'+o.netloc+tenant_suffix, errmsg_from_excp(e)), 2)

			try:
				# get 'SCOPED' token for allowed tenant
				headers = {'content-type': 'application/json', 'accept': 'application/json'}
				payload = {'auth': {'voms': True, 'tenantName': tenant}}
				response = requests.post(
					o.scheme+'://'+o.netloc+token_suffix, 
					headers=headers,
					data=json.dumps(payload), 
					cert=cert, 
					verify=False, 
					timeout=int(timeout))

				response.raise_for_status()
				token = response.json()['access']['token']['id']	

			except(KeyError, IndexError) as e:
				nagios_out('Critical', 
				'Could not fetch scoped keystone token for %s from response: Key not found %s' 
				% (tenant, errmsg_from_excp(e)), 2)
			except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
				nagios_out('Critical', 
				'Connection error %s - %s' % (o.scheme+'://'+o.netloc+token_suffix, errmsg_from_excp(e)), 2)

			try:
				tenant_id = response.json()['access']['token']['tenant']['id']

			except(KeyError, IndexError) as e:
				nagios_out('Critical', 
				'Could not fetch id for tenant %s: Key not found %s' % (tenant, errmsg_from_excp(e)), 2)

			try:
				# Get the Service Catalog from KeyStone
				service_catalog = response.json()['access']['serviceCatalog']
			except(KeyError, IndexError) as e:
				nagios_out('Critical', 
				'Could not fetch service catalog: Key not found %s' % (errmsg_from_excp(e)), 2)

			try:
				swift_endpoint = None
				for e in service_catalog:
					if e['type'] == 'object-store':
						swift_endpoint = e['endpoints'][0]['publicURL']
				assert swift_endpoint is not None
				
			except(KeyError, IndexError, AssertionError) as e:
				nagios_out('Critical', 
				'Could not fetch nova compute service URL: Key not found %s' % (errmsg_from_excp(e)), 2)	

			logger.debug ("\n- Establish a connection with the OpenStack Swift Object Storage")
		        logger.debug ("- Swift public endpoint = %s " % swift_endpoint)

			_swift = swclient.Connection(preauthurl=swift_endpoint,
                       	                preauthtoken=token,
                               	        auth_version=options.auth)

			# Creating a new Container
       	                containerID = 'container-' + str(uuid.uuid4())
               	        objectID = 'file-' + str(uuid.uuid4())
                       	data = "This is just an ASCII file\n"
                        path = "/usr/libexec/grid-monitoring/eu.egi.cloud.SWIFT/"
       	                filename = path + "filename_" + str(uuid.uuid4()) + ".txt"

			# Create a new OpenStack Swift container
                       	logger.debug ("- Create a new OpenStack Swift Container = %s " % containerID)
			result = _swift.put_container(containerID)

			# Create a new object
			logger.debug ("- Create a new object file = %s" %filename)
			_swift.put_object(containerID, objectID, data)

			# Get some statistics about the new created container
			if (verbose):
				logger.debug ('_' * 71)
		                logger.debug ("- Print container statistics")
        	       		(container, containers) = _swift.get_container(containerID)
				logger.debug ("ContainerID: %s " % containerID)
				logger.debug ("Objects: %(x-container-object-count)s" % container)

		                for container in containers:
       			                logger.debug (">>> %(name)s [%(bytes)d bytes]" % container)
                	       		logger.debug (">>> %(content_type)s [MD5SUM: %(hash)s]" % container)

                		logger.debug ('_' * 71)

			# Download object file
			logger.debug ("- Download the object file in the local file")
			response, object_body = _swift.get_object(containerID, objectID)
			f = open(filename, 'wb')
	                f.write(object_body)
       		        f.close()

			# Delete the object file
			logger.debug ("- Delete the objectID = " + objectID)
			_swift.delete_object(containerID, objectID)

			# Delete the OpenStack Swift Container
			logger.debug ("- Delete the OpenStack Swift Container = %s" % containerID)
			_swift.delete_container(containerID)

			# Closing connection
			logger.debug ("- Close connection with the OpenStack Swift Object Storage")
			_swift.close()
			

if __name__ == "__main__":
        main()
