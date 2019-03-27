from ModSecurity import ModSecurity, Rules, Transaction, ModSecurityIntervention
import os
import sys
import re
from urllib.parse import unquote,quote
import json
import time


class MSecAnalyzer():
    def __init__(self,req = b'', modsec=None, modsec_rule=None):
        # Initialize  method,uri,version,headers
        # try get modsec module and rules and load rules
        try:
            self.req = req.decode()
            self.header = self.data = self.method = self.uri = self.version = self.headers = self.resultLog = ""
            self.auditLog = modsec
            self.modsec_rule = modsec_rule
        except ValueError:
            print ("Invalid request")
        except:
            print("Error")


    def splitHeaderData(self,data):
        """Split header and data"""
        
        # End Of Head
        eoh = data.find('\r\n\r\n')
        # Start Of Content
        soc = eoh + 4

        if eoh == -1:
            eoh = data.find('\n\n')
            soc = eoh + 2
        if eoh == -1:
            return 0

        return (data[0:eoh],data[soc:])



    def parseRequest(self,req):
        """Split header to several part: method,uri,version,headers && strip \r -  avoid false positive"""

        method = uri = version = ""
        headers = list()
        lines = req.split('\n')

        try:
            method, uri, version = lines.pop(0).split(' ')
            # Version of HTTP -only get number, - trim 'HTTP/'
            version = version.split('/')[1].strip('\r')
        except ValueError:
            print ('Invalid request')

        while lines:
            line = lines.pop(0)
            if not line:
                break
            headers.append(line.strip('\r'))

        return method, uri, version, headers


    def analyzeReq(self):
        """Analyse the request using modsec"""
        
        self.header,self.data = self.splitHeaderData(self.req)
        self.method, self.uri, self.version, self.headers = self.parseRequest(self.header)

        try:
            modsec = ModSecurity()
            rules = Rules()
            rules.loadFromUri(self.modsec_rule)
            transaction = Transaction(modsec, rules, None)
        except rules.getParserError():
            print ("Unable to parse rules: %s " % rules.getParserError())


        for header in self.headers:
            # split the headers with ": ", as for each key and value in the string is separated by ": "
            transaction.addRequestHeader(*header.split(': '))

        if self.data:
            transaction.appendRequestBody(self.data.strip(r' \t\r\n\0'))

        transaction.processURI(self.uri, self.method, self.version)
        transaction.processRequestHeaders()
        transaction.processRequestBody()
        transaction.processLogging()


    def getValueByKey(self,listStr,key):
        """
        From the list of string, find the key in the string to separate the key and value
        Example each data in listStr [msg "This is example"]
        Example key sent is msg
        """
        for x in listStr:
            if key in x:
                return x
        return 0


    def getAttackType(self,attackStr):
        # Get type of attack
        listAttacks = re.findall(r"(?:SQLI=\d+|XSS=\d+|RFI=\d+|LFI=\d+|RCE=\d+|PHPI=\d+|HTTP=\d+|SESS=\d+)",attackStr,re.IGNORECASE)

        joinAttacks = ""

        for x in listAttacks:
            if x.split("=")[1] != '0':
                if not joinAttacks:
                    joinAttacks = '"' + x.split("=")[0] + '"'
                else:
                    joinAttacks = ', "' + x.split("=")[0] + '"'

        if not joinAttacks:
            joinAttacks = '"unknown"'

        return joinAttacks


    def getMeanSeverity(self, listSeverity):

        totalSeverity = 0
        for x in listSeverity:
            totalSeverity = totalSeverity + int(x['severity'])

        if listSeverity:
            return int(totalSeverity/len(listSeverity))

        return 0


    def headerToJSON(self):

        dictHeader = {}
        for x in self.headers:
            dictHeader[x.split(': ')[0]] = x.split(': ')[1]

        return dictHeader


    def getModSecStatus(self):

        if not self.resultLog:
            self.resultLog = self.readFromFile()

        if self.resultLog:
            return True
        else:
            return False

    def readFromFile(self):
        """Get log data from file convert to dict == JSON"""
        try:
            with open(self.auditLog, 'r') as f:
                reader = f.read()
            with open(self.auditLog, 'w'): pass
        except:
            print("Error in get log data")
            return 0
        
        return reader


    def getModSecResult(self):
       
        # if not self.resultLog:
        #     self.resultLog = self.readFromFile()

        if self.getModSecStatus():
            # Create list from audit log - only get modsec log
            modSecLists = re.findall(r"\[id.*? \[unique_id .*?\]",self.resultLog,re.IGNORECASE)

            # Empty list
            dictfModSec = {}
            listModSec = []
            listTags = ""

            for modSec in modSecLists:

                modSecTags = re.findall(r"(\[.*?\])",modSec)
                perModSec = {}


                if 'Inbound Anomaly Score Exceeded' in modSec:
                    if 'event-correlation' in modSec:
                        # trim [,],",(msg )in the modSecTags 
                        dictfModSec["detail"] = re.sub(r"([\[\]\"]|(msg ))",r"",self.getValueByKey(modSecTags,'msg'))
                    continue

                for eachTag in modSecTags:
                    rawTag = re.sub(r"[\[\]]",r"",eachTag)
                    eok = rawTag.find(' "')
                    perTag = {}


                    # Classify all tag under one tag
                    if rawTag[:eok] == "tag":
                        if not listTags:
                            listTags = '"' + re.sub(r"[\"]",r"",rawTag[eok+1:]) + '"'
                        if re.sub(r"[\"]",r"",rawTag[eok+1:]) not in listTags:
                            listTags = listTags +', "' + re.sub(r"[\"]",r"",rawTag[eok+1:]) + '"'
                    else:
                        if rawTag[:eok] not in ("accuracy","unique_id","rev","hostname","uri"):
                            if rawTag[:eok] == "id":
                                perModSec["sig_id"] = re.sub(r"[\"]",r"",rawTag[eok+1:])
                                continue
                            if rawTag[:eok] == "msg":
                                perModSec["sig_name"] = re.sub(r"[\"]",r"",rawTag[eok+1:])
                                continue
                            perModSec[rawTag[:eok]] = str(re.sub(r"[\"]",r"",rawTag[eok+1:]))
           
                listModSec.append(perModSec)


            dictfModSec["modsec"] = listModSec
            dictfModSec["tags"] = listTags
            dictfModSec["http_method"] = self.method
            dictfModSec["headers"] = self.headerToJSON()
            dictfModSec["raw_request"] = self.req
            dictfModSec["url_path"] = unquote(self.uri)
            dictfModSec["event_name"] = '"webattack","modsec"'  
            if dictfModSec.get("details"): 
                dictfModSec["attack_type"] = self.getAttackType(dictfModSec["detail"])
            else:
                dictfModSec["attack_type"] = ""
            dictfModSec["post_payload"] = unquote(self.data)
            dictfModSec["severity"] = self.getMeanSeverity(listModSec)
            dictfModSec["timestamp"] = str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            
            return json.dumps(dictfModSec)

        return 0
