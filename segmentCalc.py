
'''
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


usagage: segmentCalc.py --xml filename --out directory --segment <segment name to append results in xml>


Future Work:
logging, better debugging/exception handling, simplification of code



'''

from lxml import etree #process xml files
from StringIO import StringIO
from random import randint 
from netaddr import *  # all the heavy lifting
import time
import csv #manage output
import sys
import argparse #manage args
import os #manage filesystem 

#GLOBALS
NETWORKS = [2,6,14,30,62,126,254,510,1022,2046,4094,8190,16382,32766,65534,131070,262142,524286]

class _CSVWriter:

    def __init__(self, fileName):
        try:
            # create a writer object and then write the header row
            self.csvFile = open(fileName, 'wb')
            self.writer = csv.writer(self.csvFile, delimiter=',', quoting=csv.QUOTE_ALL)
            self.writer.writerow( ('addressInt', 'OrigFirst', 'OrigLast', 'Cidr', 'IPRange', 'LengthOfRange') )
        except:
            print 'CSV File Failure'

    def writeCSVRow(self, int1, first, last, cidr,iprange,lenRange):
        self.writer.writerow( (int1, first, last, cidr,iprange,lenRange))

    def writerClose(self):
        self.csvFile.close()





def generateID(n):
    nId = ''.join(["%s" % randint(0, 9) for num in range(0, n)])
    return nId

def writeCSV(o_result,vals):
    if len(vals) ==6:
        o_result.writeCSVRow(vals[0],str(vals[1]),str(vals[2]),str(vals[3]),str(vals[4]), str(vals[5]))
    else:
        length = len(vals[3])
        o_result.writeCSVRow("",str(vals[0]),str(vals[1]),str(vals[2]),str(vals[3]),str(length))

def parseXML(xmlFile):
    """
    Parse the xml
    """
    f = open(xmlFile)
    xml = f.read()
    f.close()
    ranges = []
 
    tree = etree.parse(StringIO(xml))
    context = etree.iterparse(StringIO(xml))
    for action, elem in context:
        if not elem.text:
            text = "None"
        else:
            text = elem.text
        if elem.tag =="RANGES":
            t = elem.attrib["RANGE"]
            
         
            print("[+] extracted: " + t)
            ranges.append(t)
    return(ranges)



def processRanges(t,oCVS):
    print("[+] Processing: " + t)
    t = t.split('-')
    t[0] = IPAddress(t[0]) #create ip address objects
    t[1] = IPAddress(t[1])
    t.insert(0, int(t[0])) #create int representation for acruate sorting
    iplist = IPRange(t[1],t[2])
    length = len(iplist)
    if checkIfStandard(length):
        print("[+] Standard Range")
        nRange,cidr = fixcidr(iplist,getMask(length))
    
        t.append(cidr)
        t.append(nRange)
        t.append(int(t[2])-int(t[1]))
        writeCSV(oCVS, t)
        print("[!]FINISHED processing: " + str(t))
    else:
        print("[+] NON-Standard Range")
        nRange,cidr = nFixcidr(iplist)
        t.append(cidr)
        t.append(nRange)
        t.append(int(t[2])-int(t[1]))
        writeCSV(oCVS, t)        
        print("[!]FINISHED processing: " + str(t))
    return t  

       
def ndiff(fsSet):
    private = IPSet(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])
    diffSet = private - fsSet
    
    return diffSet 
    
def nFixcidr(iplist):
    #Non-standard Range uses cidr_merge to determine subnets covered in the Range
    nRange = iplist
    listCidr = cidr_merge(list(nRange))
    rangeList = IPSet()
    for cidr in listCidr:
        rangeList.add(cidr)
    rangeList = list(rangeList.iter_ipranges())
        
    return rangeList, listCidr
        


    
def fixcidr(iplist,mask):
  
    allhosts = []
    allhosts.append([ip for ip in IPNetwork(str(iplist[0])+mask).iter_hosts()])
    cidr = IPSet()
    nRange = IPSet()
    network = IPNetwork(str(allhosts[0][0])+ mask)
    '''
    Test if a subnet isn't cidr aligned .ie a /22 that doesn't fall on octect divisble by 4 suchas .61 rather than .60
    Are there a bunch of ip's in the range that are outside the assumed subnet?
    if yes, fix it by defaulting to the IPRange.cidrs() in the range, better way to do this for sure.
    '''  
    cidr.add(network)
    nRange.add(iplist)

#===============================================================================
    # >4 is arbitrary but seems to work for my use cases.
    if len(cidr - nRange) > 4: 
        #not cidr aligned 
        #print("error") debugging
        cidr.clear()
        nRange.clear()
        for rNet in iplist.cidrs():
            cidr.add(rNet)
#===============================================================================    
    
    nRange.add(IPRange(network.network, network.broadcast))
    cidr = list(cidr.iter_cidrs())
    nRange = list(nRange.iter_ipranges())
    #print(nRange)
    print("[+] Corrected Network Cidr: " + str(cidr))
    
    return nRange,cidr
    

def writeXml(diffSet,xmlFile,xCVS):
 
    nId = generateID(18) # generate random segmentid
    tree = etree.parse(xmlFile)
    segment = "GROUP[@NAME='%s']" % segment_name # Select the element we want to work on and append to
    t = tree.find(segment) 
    subTag = etree.Element("GROUP", DECRIPTION="", NAME="UNASSIGNED", SEGMENT_ID=nId)
    diffSet = list(diffSet.iter_cidrs()) 
    for i in diffSet:
        #print(i) debugging 
        if i.broadcast != None:
            first = i.network +1 #return to ForeScout CounterACT segment format ignoring network and broadcast where possible
            last = i.broadcast -1
        elif len(list(i.iter_hosts())) == 1:
            first,last = i.ip, i.ip
        else:
            first, last = i.network, i.network + 1

        nRange = str(first) + "-" + str(last)
        vals = [first,last,i,nRange]
        writeCSV(xCVS,vals)
        subText = etree.SubElement(subTag, "RANGES", RANGE=nRange) 
    
    t.append(subTag)     
    
    #append new- to updated xml
    newXml = output_path+"\\new-"+input_xml
    f = open(newXml,'w')
    f.write(etree.tostring(tree, pretty_print=True))
    f.close()    

def checkIfStandard(length):
    number = min(NETWORKS, key=lambda x:abs(x-length))
    if abs(number - length) < 4:
        return True
    else:
        return False

def getMask(length):
    
    number = min(NETWORKS, key=lambda x:abs(x-length))
    if number == 6:
        mask = "/29"
        
    elif number == 14:
        mask = "/28"
    elif number == 30:
        mask = "/27"
    elif number == 62:
        mask = "/26"
    elif number == 126:
        mask = "/25"
    elif number == 254:
        mask = "/24"
    elif number == 510:
        mask = "/23"
    elif number == 1022:
        mask = "/22"
    elif number == 2046:
        mask = "/21"
    elif number == 4094:
        mask = "/20"
    elif number == 8190:
        mask = "/19"
    elif number == 16382:
        mask = "/18"
    elif number == 32766:
        mask = "/17"
    elif number == 65534:
        mask = "/16"
    elif number == 131070:
        mask = "/15"
    elif number == 262142:
        mask = "/14"
    elif number == 524286:
        mask = "/13"  
    
    return mask


def ValidateFile(theFile):

    # Validate the path is a directory
    if not os.path.isfile(theFile):
        raise argparse.ArgumentTypeError('File does not exist')

    # Validate the path is readable
    if os.access(theFile, os.R_OK):
        return theFile
    else:
        raise argparse.ArgumentTypeError('File is not readable')


def ValidateDirectory(theDir):

    # Validate the path is a directory
    if not os.path.isdir(theDir):
        raise argparse.ArgumentTypeError('Directory does not exist')

    # Validate the path is readable
    if os.access(theDir, os.R_OK):
        return theDir
    else:
        raise argparse.ArgumentTypeError('Directory is not readable')

def main():
    
    #=================================
    #  PARSE arguments
    #=================================
    
    parser = argparse.ArgumentParser(description='Attempt to parse the attachment from EML messages.')
    parser.add_argument('-x', '--xml', type= ValidateFile, required=True, help='ForeScout CounterACTSegment XML file to read')
    parser.add_argument('-o', '--out', type= ValidateDirectory, required=True, help='Directory to write new Segments file and log data')
    parser.add_argument('-s', '--segment', required=True, help='Segment name to append new ranges to')
         
    
    
    global args, input_xml, output_path, segment_name
    # parse 
    args = parser.parse_args()    

    if args.xml:
        input_xml = args.xml
    
    if args.out:
        output_path = args.out
    
    if args.segment:
        segment_name = args.segment
        
    #=================================
    #  END PARSE arguments
    #=================================    
    
    
    print "[+] starting script.."
    startTime = time.time()      
        
    oCVS = _CSVWriter(output_path +'\\outputReport.csv')
    xCVS = _CSVWriter(output_path +'\\diffReport.csv')
    
    r = parseXML(input_xml)
    r.sort()
    fsSet = IPSet()
    allNetData = []
    recordNum = 0
   
    for fsRange in r:
        
        allNetData.append(processRanges(fsRange,oCVS))
        cNet = allNetData[recordNum][3]
        print("[+] Adding to Set: " + str(cNet))
        for nNet in cNet:
            fsSet.add(nNet)
        print("#ROUND: %s") % str(recordNum)
        #print("[+] Current Set %s: " + str(fsSet)) % str(recordNum)
        recordNum +=1
    
    #write append ranges to new Unassigned segment under the specificified segment argument
    writeXml(ndiff(fsSet),input_xml,xCVS)
    
    print "[+] Script Completed"   
    elapsedTime = time.time() - startTime
    print'[+] Elapsed Time: ', elapsedTime, 'Seconds'       

    
if __name__ == "__main__":
    
    main()
    
   
