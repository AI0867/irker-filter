Irker Filter
============

Public-to-local filter for irker. Listens on whatever your public IP is, and passes it on to localhost if it matches a filter.

Invocation
----------
    irker-filter.py

filter.json must be present in the same directory.

filter.json
-----------

The file contains a list of dicts. Each dict is a filter that, if matched, allows the message to pass to the local irkerd. The dicts can have the following keys, all of which, if present, have to match:

* privmsg: A regex that has to match the 'privmsg' part of the irker message.
* to: A regex that has to match the 'to' part of the irker message.
* ip: (List of) CIDR-style IP masks: 10.1.0.0/16, fec0::/10
* host: A hostname for which the DNS results must contain the source IP.
