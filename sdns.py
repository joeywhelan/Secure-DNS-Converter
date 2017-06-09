'''
Created on May 22, 2017

@author: joey
'''
import configparser
import socketserver
import requests
import logging.config
from apscheduler.schedulers.background import BackgroundScheduler
from stem import Signal
from stem.control import Controller

GOOGLE_DNS = 'https://dns.google.com/resolve'
PROXIES = {'http':  'socks5://127.0.0.1:9050',
           'https': 'socks5://127.0.0.1:9050'} 


class DNSHandler(socketserver.BaseRequestHandler):
    
    def handle(self):
        """Main function.  
        
        Args:
            self: Instance reference 
        
        Returns:
            None
                
        Raises:
            None
        """
        logging.debug('Entering handle()')
        data = self.request[0]
        socket = self.request[1]
        response = self.__createResponse(data)
        socket.sendto(response, self.client_address)
        logging.debug('Exiting handle()')
        
    def __processQuestion(self, quesData):
        """Parses the question portion of a DNS request into objects
        
        Types are determined via attempts at casting and evaluating any exceptions raised.
        
        Args:
            self: Instance reference 
            quesData: Question portion of the DNS request, in a byte array
        
        Returns:
            name: the domain name (byte array)
            queryType: DNS query type (string)
            question:  entire question portion of DNS request (byte array)
            
        
        Raises:
            None
        """
        logging.debug('Entering __processQuestion()')
        i = 0
        name = ''
        
        while True:
            count = int.from_bytes(quesData[i:i+1], byteorder='big')
            i = i+1
            if count == 0:
                break
            else:
                name = name + str(quesData[i:i+count],'utf-8') + '.'
                i = i + count
            
        name = name[:-1]
        queryType = str(int.from_bytes(quesData[i:i+2], byteorder='big'))
        
        question = quesData[0:i+4]
        logging.debug('name: ' + name + ' queryType: ' + queryType)
        logging.debug('Exiting __processQuestion()')
        return name, queryType, question
    
    def __getFlags(self, data):
        """Parses out the flag bits of the DNS request and creates a flag field for the response
        
        Args:
            self: Instance reference 
            data: Flags portion of the DNS request, in a byte array
        
        Returns:
            flags: new flags field for the DNS response (byte array)
                
        Raises:
            None
        """
        logging.debug('Entering __getFlags()')
        flags = 0b100000 #qr=1, opcode=0000, aa=0
        flags = (flags << 1) | data['TC'] #set tc bit
        flags = (flags << 1) | data['RD'] #set rd bit
        flags = (flags << 1) | data['RA'] #set ra bit
        flags = flags << 1 #One zero
        flags = (flags << 1) | data['AD'] #set ad bit
        flags = (flags << 1) | data['CD'] #set cd bit
        flags = ((flags << 4) | data['Status']).to_bytes(2, byteorder='big') 
        logging.debug('flags: ' + str(flags))
        logging.debug('Exiting __getFlags()')
        return flags
        
    def __getRecords(self, name): 
        """Issues a DNS over HTTPS request to Google with the name from the original DNS request
        
        Args:
            self: Instance reference 
            data: name in DNS request, in a byte array
        
        Returns:
            flags: new flags field for the DNS response (byte array)
            numbers: number of records field for the DNS response (byte array)
            records: DNS response records (byte array)
                
        Raises:
            None
        """
        logging.debug('Entering __getRecords()') 
        payload = {'name' : name, 'type' : '1'}
        #data = requests.get(GOOGLE_DNS, params=payload).json()
        data = requests.get(GOOGLE_DNS, params=payload, proxies=PROXIES).json()
        
        logging.debug(data) 
        flags = self.__getFlags(data)
        records = bytes(0)
        count = 0
        if 'Answer' in data:
            for answer in data['Answer']:
                if answer['type'] == 1:
                    count = count + 1
                    name = (0xc00c).to_bytes(2, byteorder='big') #RFC departure.  Hard-coded offset to domain name in initial question.
                    rectype = (1).to_bytes(2, byteorder='big')
                    classtype = (1).to_bytes(2, byteorder='big')
                    ttl = answer['TTL'].to_bytes(4, byteorder='big')
                    length = (4).to_bytes(2, byteorder='big') #4 byte IP addresses only
                    quad = list(map(int, answer['data'].split('.')))
                    res = bytes(0)
                    for i in quad:
                        res = res + i.to_bytes(1, byteorder='big')
                    records = records + name + rectype + classtype + ttl + length + res
        
        nques = (1).to_bytes(2, byteorder='big') #hard coded to 1
        nans = (count).to_bytes(2, byteorder='big')
        nath = (0).to_bytes(2, byteorder='big')    #hard coded to 0
        nadd = (0).to_bytes(2, byteorder='big') #hard coded to 0
        numbers = nques + nans + nath + nadd
        logging.debug('numbers: ' + str(numbers))
        logging.debug('records: ' + str(records))
        logging.debug('Exiting __getRecords()')  
        return flags, numbers, records
     
    def __createResponse(self, data):
        """Verifies the request is a standard, A query and then creates a DNS response
        
        Args:
            self: Instance reference 
            data: byte array respresenting the DNS request
        
        Returns:
            response: byte array respresenting the DNS response
                
        Raises:
            None
        """
        logging.debug('Entering __createResponse()')
        tid = data[0:2] #transaction id
        opcode = data[2] & 0b01111000   #data[2] is the flags field. bits 2-5 is the opcode  
        name, queryType, question = self.__processQuestion(data[12:]) 
        
        if opcode == 0 and queryType == '1':  #RFC departure.  Only processing standard queries (0) and 'A' query types.  
            flags, numbers, records = self.__getRecords(name)
            response = tid + flags + numbers + question + records
        else:
            #qr (response), recursion desired, recursion avail bits set.  set the rcode to 'not implemented'
            flags = ((0b100000011000 << 4) | 4).to_bytes(2, byteorder='big') 
            numbers = (0).to_bytes(8, byteorder='big')
            response = tid + flags + numbers
        
        logging.debug('response: ' + str(response))
        logging.debug('Exiting __createResponse()')
        return response
       
    

def renew():
    """Changes IP Address of Tor circuit
        
        Sends a signal to the local Tor controller to force it to obtain a new IP address
        Args:
            None
        
        Returns:
            None
        
        Raises:
            None
    """
    with Controller.from_port(port = 9051) as controller:
        controller.authenticate(password="test")
        controller.signal(Signal.NEWNYM)
            
if __name__ == '__main__':
    #Set up a background scheduler to periodically change the Tor IP address
    scheduler = BackgroundScheduler()
    scheduler.add_job(renew, 'interval', hours=1)
    scheduler.start()
    
    #Launch UDP server
    cfgParser = configparser.ConfigParser()
    cfgParser.optionxform = str
    cfgParser.read('sdns.cfg')  
    host = cfgParser.get('ConfigData', 'host')
    port = int(cfgParser.get('ConfigData', 'port'))
    logging.config.fileConfig('./logging.conf')
    logging.debug('Starting server on port {}'.format(port))
    server = socketserver.UDPServer((host, port), DNSHandler)
    server.serve_forever()
    
