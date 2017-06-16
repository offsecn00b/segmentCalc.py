# segmentCalc.py
Processes segments xml from ForeScout CounterACT and returns a modified xml including all RFC 1918 not explicitly defined in original file

usage: segmentCalc.py --xml filename --out directory --segment <segment name to append results in xml>

Author: offsecNoob
Date: 6/17/2017
Background:


ForeScout CounterACT is a network access control solution. The tool monitors and responds to hosts in defined 
network segments. However, there are many good cases for wanting to monitor and respond to all networks. ForeScout CounterACTcan 
see all networks however, it only actively responds and processes policies for the defined networks. 
In other words if you want ForeScout to monitor and respond to all potential networks you must define all potential
networks. This isn't as easy as it sounds because you are not allowed to define segments that overlap other segments.
Large organizations can have hundreds possibly thousnads of subnets. Findind the ones not in use (not defined segments)
without overlapping other segments isn't easy.


Objective:

The objective of this script is to take a ForeScout CounterACT segments export xml file, parse it and normalize all the 
defined segment ranges then determine the cidr(s) that cover those ranges.

Some organizations may have non-standard subnetting so it attempts to accomodate those as well.

The script makes use of the netaddr library to easily manipulate ip, ip ranges, ip networks, cidrs and ipsets. The script
uses built in netaddr "diff" function to subtract the parsed list of segement ranges from all priavte network ranges RFC 1918.
The Script then appends a child to the resulting ranges that aren't explicitly defined to a specified segment(cli arg) node.
The new ranges are assigned to a node named "unassigned" so it easily recognizeable when imported back into CounterACT.
Finally the script outputs the results into a new valid xml segments file that can be imported back into forescout. This
script should be run any time major change are made to defined segments. 




Future Work:
logging, better debugging/exception handling, simplification of code
