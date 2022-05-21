'''DNS Server for Content Delivery Network (CDN)
'''

import sys
from socketserver import UDPServer, BaseRequestHandler
from utils.dns_utils import DNS_Request, DNS_Rcode
from utils.ip_utils import IP_Utils
from datetime import datetime
import math

import re
from collections import namedtuple

import random


__all__ = ["DNSServer", "DNSHandler"]


class DNSServer(UDPServer):
    def __init__(self, server_address, dns_file, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=True)
        self._dns_table = []
        self.parse_dns_file(dns_file)
        
    def parse_dns_file(self, dns_file):
        # ---------------------------------------------------
        # TODO: your codes here. Parse the dns_table.txt file
        # and load the data into self._dns_table.
        # --------------------------------------------------
        fd = open(dns_file)
        for line in fd:
            line = line.strip('\n')
            dns_entry = line.split()

            dns_entry[0].strip('.')
            pattern = dns_entry[0].replace(".","\.")
            pattern = pattern.replace("*",".+")
            pattern += "\.?"
            ret_list = dns_entry[2:]
            
            self._dns_table.append([pattern, dns_entry[1], ret_list])
        # ----------------------------------------------------

    @property
    def table(self):
        return self._dns_table


# ------------------------------------------------
# For calculate distance by (latitude, longitude)
EARTH_RADIUS = 6378.137
def rad(d):
    return d * math.pi / 180.0
# ------------------------------------------------


class DNSHandler(BaseRequestHandler):
    """
    This class receives clients' udp packet with socket handler and request data. 
    ----------------------------------------------------------------------------
    There are several objects you need to mention:
    - udp_data : the payload of udp protocol.
    - socket: connection handler to send or receive message with the client.
    - client_ip: the client's ip (ip source address).
    - client_port: the client's udp port (udp source port).
    - DNS_Request: a dns protocl tool class.
    We have written the skeleton of the dns server, all you need to do is to select
    the best response ip based on user's infomation (i.e., location).

    NOTE: This module is a very simple version of dns server, called global load ba-
          lance dns server. We suppose that this server knows all the ip addresses of 
          cache servers for any given domain_name (or cname).
    """
    
    def __init__(self, request, client_address, server):
        self.table = server.table
        super().__init__(request, client_address, server)

    def calc_distance(self, pointA, pointB):
        ''' TODO: calculate distance between two points '''
        ...
        if pointA is None or pointB is None:
            return float('inf')
        radLatA = rad(pointA[0])
        radLatB = rad(pointB[0])
        delta_lat = radLatA - radLatB
        delta_lng = rad(pointA[1]) - rad(pointB[1])
        tmp = math.pow(math.sin(delta_lat)/2, 2) + math.cos(radLatA) * math.cos(radLatB) * math.pow(math.sin(delta_lng / 2), 2) 
        L = 2 * EARTH_RADIUS * math.asin(math.sqrt(tmp))
        return L

    def get_response(self, request_domain_name):
        response_type, response_val = (None, None)
        # ------------------------------------------------
        # TODO: your codes here.
        # Determine an IP to response according to the client's IP address.
        #       set "response_ip" to "the best IP address".
        client_ip, _ = self.client_address

        for item in self.table:
            if re.match(item[0], request_domain_name): # matched
                
                if item[1] == "CNAME": # CNAME
                    response_type, response_val = ("CNAME", item[2][0])
                elif item[1] == "A": # A
                    if len(item[2]) == 1: # only one entry in item[2]
                        response_type, response_val = ("A", item[2][0])
                    elif len(item[2]) == 0: # error situation
                        self.log_error("Oops :))")
                    else:   
                        # Get a random IP address
                        response_type, response_val = ("A", item[2][random.randint(0,len(item[2]) - 1)])
                        # Get the global point
                        clientPoint = IP_Utils.getIpLocation(client_ip)
                        min_dis = float('inf')
                        # Get the best IP address 
                        if clientPoint is not None: 
                            for ip_str in item[2]:
                                serverPoint = IP_Utils.getIpLocation(ip_str)
                                tmp_dis = self.calc_distance(clientPoint, serverPoint)
                                if tmp_dis <= min_dis:
                                    min_dis = tmp_dis
                                    response_val = ip_str
                else:
                    self.log_error("Oops :))")

                break


        # -------------------------------------------------
        return (response_type, response_val)

    def handle(self):
        """
        This function is called once there is a dns request.
        """
        ## init udp data and socket.
        udp_data, socket = self.request

        ## read client-side ip address and udp port.
        client_ip, client_port = self.client_address

        ## check dns format.
        valid = DNS_Request.check_valid_format(udp_data)
        if valid:
            ## decode request into dns object and read domain_name property.
            dns_request = DNS_Request(udp_data)
            request_domain_name = str(dns_request.domain_name)
            self.log_info(f"Receving DNS request from '{client_ip}' asking for "
                          f"'{request_domain_name}'")

            # get caching server address
            response = self.get_response(request_domain_name)

            # response to client with response_ip
            if None not in response:
                dns_response = dns_request.generate_response(response)
            else:
                dns_response = DNS_Request.generate_error_response(
                                             error_code=DNS_Rcode.NXDomain)
        else:
            self.log_error(f"Receiving invalid dns request from "
                           f"'{client_ip}:{client_port}'")
            dns_response = DNS_Request.generate_error_response(
                                         error_code=DNS_Rcode.FormErr)

        socket.sendto(dns_response.raw_data, self.client_address)

    def log_info(self, msg):
        self._logMsg("Info", msg)

    def log_error(self, msg):
        self._logMsg("Error", msg)

    def log_warning(self, msg):
        self._logMsg("Warning", msg)

    def _logMsg(self, info, msg):
        ''' Log an arbitrary message.
        Used by log_info, log_warning, log_error.
        '''
        info = f"[{info}]"
        now = datetime.now().strftime("%Y/%m/%d-%H:%M:%S")
        sys.stdout.write(f"{now}| {info} {msg}\n")
