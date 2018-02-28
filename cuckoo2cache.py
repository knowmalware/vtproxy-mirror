#!/usr/bin/env python
"""
To initialise the cache I created a small program that copies
the VirusTotal results that Cuckoo already collected into the new
cache collection.
"""

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


import pymongo
from pymongo import Connection
from pprint import pprint
import sys
import json

import bson.json_util

def RunAnalysis():
    connection = Connection("localhost")
    db = connection.cuckoo
    collection = db.analysis

    vtresults = connection.virustotal.vtresults

    for post in collection.find():
        try:
            if "virustotal" in post:
                vtdata = post["virustotal"]
                print "Found VTData in Cuckoo"

                jdata = bson.json_util.dumps(vtdata)

                res = vtresults.insert(vtdata)
                print "Copied VTData into virustotal: %s" % res
        except Exception as e:
            print "Something went wrong: %s" % e
            pass

if __name__ == "__main__":
    report = RunAnalysis()

