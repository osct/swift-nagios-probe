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

import os, sys, time, pwd, datetime, optparse, time, re, uuid, grp
import logging, logging.handlers
import keystoneclient.v2_0.client as ksclient
import swiftclient.client as swclient
import swiftclient.exceptions as swclientexceptions

"""
eu.egi.cloud.SWIFT.py

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

def get_keystone_creds():
        "Reading settings from env"

        d = {}
        d['username'] = os.environ['OS_USERNAME']
        d['password'] = os.environ['OS_PASSWORD']
        d['auth_url'] = os.environ['OS_AUTH_URL']
        d['tenant_name'] = os.environ['OS_TENANT_NAME']
        return d

class OSSwift:
	swift = None

	def __init__(self, auth_url, username, password, auth_version, retries, insecure, creds, keystone, logger):
		"Initialise the class and establish a new connection with the OpenStack Object Storage"

		self.auth_url = auth_url
		self.username = username
		self.password = password
		self.auth_version = auth_version
		self.retries = retries
		self.insecure = insecure
		self.creds = creds
		self.keystone = keystone
		self.logger = logger

                # Get Swift public URL from Keystone
                swift_endpoint = self.keystone.service_catalog.url_for(service_type='object-store', endpoint_type='publicURL')
                
		self.logger.debug ("\n[-] Establish a connection with the OpenStack Swift Object Storage")
		self.logger.debug ("[-] Swift public URL = %s " % swift_endpoint)
		self.logger.debug ("[-] Initialize the OSSwift() main class")
	        self.swift = swclient.Connection(
			self.auth_url,
                	self.username,
			self.password,
                        auth_version=self.auth_version,
			retries=self.retries,
			insecure=self.insecure,
			os_options=self.creds)
		
	def create_container(self, containerID, logger):
		"NAGIOS metric to create a new Object Storage Container"
		self.logger.debug ("[-] Create a new OpenStack Swift Container = %s " % containerID)
		self.swift.put_container(containerID)
	
	def create_object(self, containerID, objectID, data, logger):
		"NAGIOS metric to create a new object file"
		self.logger.debug ("[+] Call the put_object() method")
                self.swift.put_object(containerID, objectID, data)
                self.logger.debug ("[-] Create the objectID = " + objectID)

		self.logger.debug ('_' * 71)
                self.logger.debug ("[-] Print container statistics")
                (container, containers) = self.swift.get_container(containerID)
                self.logger.debug ("ContainerID: %s " % containerID)
                self.logger.debug ("Objects: %(x-container-object-count)s" % container)

                for container in containers:
                        self.logger.debug (">>> %(name)s [%(bytes)d bytes]" % container)
                        self.logger.debug (">>> %(content_type)s [MD5SUM: %(hash)s]" % container)

                self.logger.debug ('_' * 71)
	
	def download_object(self, containerID, objectID, filename, logger):
		"NAGIOS metric to download the object file locally"
		self.logger.debug ("[+] Call the get_object() method")
		response, object_body = self.swift.get_object(containerID, objectID)
		self.logger.debug ("[-] Download the objectID in the local file [%s]" % filename)
		f = open(filename, 'wb')
                f.write(object_body)
                f.close()

		#uid = pwd.getpwnam("swift").pw_uid
		#gid = grp.getgrnam("swift").gr_gid
		#os.chown(filename, uid, gid)
		#os.chmod(filename, 750)
		
	def delete_object(self, containerID, objectID, logger):
		"NAGIOS metric to delete the object file from the Object Storrage Container"
		self.logger.debug ("[+] Call the delete_object() method")
		self.swift.delete_object(containerID, objectID)
		self.logger.debug ("[-] Delete the objectID = " + objectID)
	
	def delete_container(self, containerID, logger):
		"NAGIOS metric to delete a new Object Storage Container"
		self.logger.debug ("[-] Delete the OpenStack Swift Container = " + containerID)
		self.swift.delete_container(containerID)
	
	def close(self, logger):
		"NAGIOS metric to close any connection with the OpenStack Object Storage"
		self.logger.debug ("[+] Call the close() method")
		self.swift.close()
