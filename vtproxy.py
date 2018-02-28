#!/usr/bin/env python
"""A basic transparent HTTP proxy"""

__author__ = "Michael Boman, based on code from Erik Johansson"
__email__  = "michael@michaelboman.org, erik@ejohansson.se"
__license__= """
Copyright (c) 2012 Erik Johansson <erik@ejohansson.se>
Copyright (c) 2013 Michael Boman <michael@michaelboman.org>
 
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
USA

"""

from twisted.web import http
from twisted.internet import reactor, protocol
from twisted.python import log
import re
import sys
import urllib
import urlparse
from pprint import pprint

from pymongo import MongoClient
import bson.json_util
import json
import datetime
import operator

class ProxyClient(http.HTTPClient):
    """ The proxy client connects to the real server, fetches the resource and
    sends it back to the original client, possibly in a slightly different
    form.
    """

    def __init__(self, method, uri, postData, headers, originalRequest):
        self.method = method
        self.uri = uri
        self.postData = postData
        self.headers = headers
        self.originalRequest = originalRequest
        self.contentLength = None

    def sendRequest(self):
        log.msg("Sending request: %s %s" % (self.method, self.uri))
        self.sendCommand(self.method, self.uri)

    def sendHeaders(self):
        for key, values in self.headers:
            if key.lower() == 'connection':
                values = ['close']
            elif key.lower() == 'keep-alive':
                next

            for value in values:
                self.sendHeader(key, value)
        self.endHeaders()

    def sendPostData(self):
        log.msg("Sending POST data")
        self.transport.write(self.postData)

    def connectionMade(self):
        log.msg("HTTP connection made")
        self.sendRequest()
        self.sendHeaders()
        if self.method == 'POST':
            self.sendPostData()

    def handleStatus(self, version, code, message):
        log.msg("Got server response: %s %s %s" % (version, code, message))

        if "virustotal.com/vtapi/v2/file/report" in self.uri or "virustotal.com/vtapi/v2/url/report" in self.uri:
            postData = self.postData
            data = urlparse.parse_qs(postData)
            resource = data["resource"][0]

            if int(code) == 403:
                log.msg("Got a 403 response, putting the scan %s into pending." % resource)
                vtpending.insert({'resource' : resource})
                log.msg("Forcing 200 OK response")
                code = 200

            if int(code) == 204:
                log.msg("Exceed the public API request rate limit")
                message = "Exceed the public API request rate limit"

        self.originalRequest.setResponseCode(int(code), message)

    def handleHeader(self, key, value):
        if key.lower() == 'content-length':
            self.contentLength = value
        else:
            self.originalRequest.responseHeaders.addRawHeader(key, value)

    def handleResponse(self, data):
        data = self.originalRequest.processResponse(data)

        if self.contentLength != None:
            self.originalRequest.setHeader('Content-Length', len(data))

        try:
            virustotal = json.loads(data)
            if virustotal["response_code"] == 1:
                log.msg("Virustotal report for resource %s exists" % virustotal["resource"])
                if "scans" in virustotal:
                    virustotal["scans"] = dict([(engine.replace(".", "_"), signature) for engine, signature in virustotal["scans"].items()])
                ret = vtresults.insert(virustotal)
                log.msg("Virustotal result stored in MongoDB: %s" % ret)
                log.msg("Deleting resource from 'vtpending' collecting, if exists")
                vtpending.remove({'resource' : virustotal["resource"]})
            elif virustotal["response_code"] == -2:
                log.msg("Virustotal report for resource %s is pending" % virustotal["resource"])
                vtpending.insert({'resource' : virustotal["resource"]})
        except Exception:
            pass

        self.originalRequest.write(data)
        self.originalRequest.finish()
        self.transport.loseConnection()

class ProxyClientFactory(protocol.ClientFactory):
    def __init__(self, method, uri, postData, headers, originalRequest):
        self.protocol = ProxyClient
        self.method = method
        self.uri = uri
        self.postData = postData
        self.headers = headers
        self.originalRequest = originalRequest

    def buildProtocol(self, addr):
        return self.protocol(self.method, self.uri, self.postData,
                             self.headers, self.originalRequest)

    def clientConnectionFailed(self, connector, reason):
        log.err("Server connection failed: %s" % reason)
        self.originalRequest.setResponseCode(504)
        self.originalRequest.finish()

class ProxyRequest(http.Request):
    def __init__(self, channel, queued, reactor=reactor):
        http.Request.__init__(self, channel, queued)
        self.reactor = reactor

    def process(self):
        host = self.getHeader('host')
        if not host:
            log.err("No host header given")
            self.setResponseCode(400)
            self.finish()
            return

        port = 80
        if ':' in host:
            host, port = host.split(':')
            port = int(port)

        self.setHost(host, port)

        self.content.seek(0, 0)
        postData = self.content.read()

        if not "virustotal.com/vtapi/v2/file/report" in self.uri and not "virustotal.com/vtapi/v2/url/report" in self.uri:
            factory = ProxyClientFactory(self.method, self.uri, postData,
                                         self.requestHeaders.getAllRawHeaders(),
                                         self)

            self.reactor.connectTCP(host, port, factory)
        else:
            data = urlparse.parse_qs(postData)

            # Have we a cached copy of this result?
            resource = data["resource"][0]
            post = list(vtresults.find({'$or':[{'md5':resource},{'resource':resource},{'sha1':resource},{'sha256':resource}]}))

            if post:
                log.msg("Found cached result for resource %s" % resource)
                self.setResponseCode(200)
                self.setHeader("content-type","application/json")
                self.write(bson.json_util.dumps(post[0]))
                self.finish()
                return
            else:
                log.msg("No cached result found for resource %s" % resource)

                factory = ProxyClientFactory(self.method, self.uri, postData,
                                             self.requestHeaders.getAllRawHeaders(),
                                             self)

                self.reactor.connectTCP(host, port, factory)


    def processResponse(self, data):
        return data

class TransparentProxy(http.HTTPChannel):
    requestFactory = ProxyRequest
 
class ProxyFactory(http.HTTPFactory):
    protocol = TransparentProxy

log.startLogging(sys.stdout)

mongohost = "localhost"
try:
    mongohost = sys.argv[1]
except Exception:
    pass

# Connecting to a MongoDB instance
log.msg("Connecting to %s" % mongohost)
client = MongoClient(mongohost)

# Map up the MongoDB collections
virustotal = client.virustotal
vtresults = virustotal.vtresults
vtpending = virustotal.vtpending

reactor.listenTCP(8000, ProxyFactory())
reactor.run()
