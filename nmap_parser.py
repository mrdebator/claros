"""
This module is used to parse the output of nmap scans.
"""
import xml.etree.ElementTree as ET
import ipaddress
import logging

class NmapPort:
    def __init__(self, port: str, state: str, service: str = "", version: str = ""):
        self.port = port
        self.state = state
        self.service = service
        self.version = version

class NmapHost:
    def __init__(self, ip: str, hostname: str, ports: list[NmapPort]):
        # self.ip = ip
        self.hostname = hostname
        self.ports = ports

        if self.is_valid_ip(ip):
            self.ip = ip

    def is_valid_ip(self, ip: str) -> bool:
        try: 
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

class NmapScan:
    def __init__(self, filename: str):
        self.filename = filename
        self.hosts: list[NmapHost] = []
        try:
            tree = ET.parse(filename)
            root = tree.getroot()
            if root.tag != 'nmaprun':
                logging.error("ERROR: Invalid Nmap XML file")
                return 
            
            for host in root.findall('host'):
                address = host.find('address').get('addr')
                hostname = ""
                for hostname in host.findall('hostnames/hostname'):
                    if hostname.get('type') == 'user':
                        hostname = hostname.get('name')
                        break
                ports = []
                for port in host.findall('ports/port'):
                    port_number = port.get('portid')
                    state = port.find('state').get('state')
                    try:
                        service = port.find('service').get('name')
                        version = port.find('service').get('product') + " " + port.find('service').get('version')
                    except: 
                        service = ""
                        version = ""
                    ports.append(NmapPort(port_number, state, service, version))
                self.hosts.append(NmapHost(address, hostname, ports))
        except Exception as e:
            logging.error(e)
            logging.error("ERROR: Unable to parse Nmap XML file.")

    def __str__(self) -> str:
        return f"Filename: {self.filename} Hosts: {self.hosts}"

