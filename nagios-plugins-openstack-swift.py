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

import eu_egi_cloud_SWIFT

import os, sys, time, pwd, datetime, optparse, time, re, uuid, grp
import logging, logging.handlers
import keystoneclient.v2_0.client as ksclient
import swiftclient.client as swclient
import swiftclient.exceptions as swclientexceptions

"""
nagios-plugins-openstack-swift.py

This is a new NAGIOS probe for testing some OpenStack SWIFT functionalities.
The new probe performs the following operations:
- Creates a new swift container;
- Create a new swift object file;
- Download the content of the object file locally;
- Delete the swift object file;
- Delete the swift container.
"""

__author__    = "Giuseppe LA ROCCA"
__email__    = "giuseppe.larocca@ct.infn.it"
__version__   = "$Revision: 0.0.3 $"
__date__      = "$Date: 22/10/2015 11:04:19 $"
__copyright__ = "Copyright (c) 2015 INFN"
__license__   = "Apache Licence v2.0"


def main():
	parser = optparse.OptionParser()

        parser.add_option(
                '-f', '--stdout-file', dest="std",
                help="The standart output where redirect the cron",
                metavar="filename")

        parser.add_option(
                '-a', '--auth', dest="auth",
                help="The Auth version. Default value is 2.0",
                metavar="double")

        parser.add_option(
                '-r', '--retries', dest="retries",
                help="Number of times to retry the request before failing. Default is 5",
                metavar="integer")

        options, args = parser.parse_args()

        if ((options.std) == None):
                # stop the program and print an error message
                print """
        Usage: nagios-plugins-openstack-swift.py [options]

        options:
          -h, --help            Show this help message and exit

          -f=filename, --stdout-file=filename
                                The standart output where redirect the cron

          -a=auth, --auth=double
                                The Auth version. Default value is 2.0

          -r=retries, --retries=double
                                Number of times to retry the request before failing. Default is 5
        """

	else:
                now = datetime.datetime.now()
                today = now.ctime()

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

                if ((options.auth) == None):
                        options.auth='2.0'

                if ((options.retries) == None):
                        options.retries='5'

                logger.debug ("\nStart NAGIOS probe at %s \n" % today)
		# Authenticating against a Keystone endpoint
                creds = eu_egi_cloud_SWIFT.get_keystone_creds()

                # Get credentials
                logger.debug ("[ Loading OpenStack environment settings ]")
                logger.debug ("username = %s " % creds['username'])
                #logger.debug ("password = %s " % creds['password'])
                logger.debug ("auth_url = %s " % creds['auth_url'])
                logger.debug ("tenant_name = %s " % creds['tenant_name'])

                # Get token from Keystone
                keystone = ksclient.Client(**creds)
                keystone.auth_token
                #logger.debug ("\nToken = %s " % keystone.auth_token)

		# Creating a new Container
                containerID = 'container-' + str(uuid.uuid4())
                objectID = 'file-' + str(uuid.uuid4())
                data = "This is just an ASCII file\n"
		path = "/usr/libexec/grid-monitoring/eu.egi.cloud.SWIFT/"
                filename = path + "filename_" + str(uuid.uuid4()) + ".txt"

		# Initialize the Swift Class
		swift = eu_egi_cloud_SWIFT.OSSwift(
			creds['auth_url'], creds['username'], creds['password'], 
			options.auth, options.retries, False, creds,
                        keystone, logger)

		# Create a new OpenStack Swift Container
		swift.create_container(containerID, logger)
		# Create a new object
		swift.create_object(containerID, objectID, data, logger)
		# Download object file
		swift.download_object(containerID, objectID, filename, logger)
		# Delete the object file
		swift.delete_object(containerID, objectID, logger)
		# Delete the OpenStack Swift Container
		swift.delete_container(containerID, logger)
		# Closing connection
		swift.close(logger)

                logger.debug ("\nStop NAGIOS probe at %s \n" % today)


if __name__ == "__main__":
        main()
