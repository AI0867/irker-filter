#!/usr/bin/python

import json
import urllib2

response = json.load(urllib2.urlopen("https://api.github.com/meta"))
filt = [ {"ip":response["hooks"], "to":"irc://chat.freenode.net/.*"} ]
json.dump(filt, open("filter.json", "w"), indent=True)
