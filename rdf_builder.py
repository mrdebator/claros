import os
import logging
from rdflib import *
from datamodels import NVDVulnerability, NVDVulnerabilityWrapper, NVDWeakness
from nmap_parser import NmapHost, NmapPort

# Relations

# CVE -> hasWeakness -> CWE
# CVE -> hasExploit -> Exploit
# IP -> hasDomainName -> Domain
# Domain -> isRelatedTo -> Domain
    # Domain -> hasOccurrences -> frequencies (Literal)
# IP -> hasService -> Service
    # IP -> hasDomainName -> Hostname (Domain Class)
    # IP -> hasPort -> Port (Literal, from NmapPort)
    # Port -> hasService -> Service + Version (Literal, from NmapPort)
# Service -> hasVulnerability -> CVE


class RDFBuilder:
    namespace: str = ""
    graph: Graph = None
    CVE = ''
    CWE = ''
    Exploit = ''
    Domain = ''
    IP = ''
    Service = ''

    def __init__(self, filepath: str = ''):
        if filepath != '':
            try: 
                self.load_ontology(filepath)
            except Exception as e:
                logging.error(e)
                logging.error("Could not load ontology. Creating new ontology.")
                self.create_ontology(namespace="http://example.org/test#")
                self.create_ontology_properties(self.graph)
        else:
            self.namespace = "http://example.org/test#"
            self.create_ontology()
            self.create_ontology_properties(self.graph)

    def load_ontology(self, filepath: str = ''):
        if os.path.isfile(filepath):
            try:
                self.graph = Graph()
                self.graph.parse(filepath)
                self.namespace = self.get_namespace(self.graph)
            except Exception as e:
                logging.error(e)
                logging.error("ERROR: Unable to parse ontology file.")
                raise e
        else:
            raise ValueError("ERROR: Filepath does not exist.")
            
    def create_ontology(self):
        if self.namespace == '':
            logging.error("ERROR: No namespace provided.")
            return
        try:
            self.graph = Graph()
            self.graph.bind("ns", self.namespace)
        except Exception as e:
            logging.error(e)
            logging.error("ERROR: Unable to create ontology.")
        
    def get_namespace(self, graph: Graph):
        if graph is None:
            logging.error("ERROR: No ontology provided.")
            return None
        for ns_prefix, namespace in graph.namespaces():
            if not ns_prefix:
                self.namespace = namespace

    def create_ontology_properties(self, graph: Graph) -> bool:
        if graph is None:
            logging.error("ERROR: No ontology provided.")
            return False
        try:
            # self.namespace = self.get_namespace(graph)
            # if self.namespace == "":
            #     logging.error("ERROR: No namespace found in graph.")
            #     return False
            
            # Domain Properties
            self.Domain = URIRef(self.namespace + "Domain")
            graph.add((self.Domain, RDF.type, RDFS.Class))

            self.hasOccurrences = URIRef(self.namespace + "hasOccurrences")
            graph.add((self.hasOccurrences, RDF.type, RDF.Property))
            graph.add((self.hasOccurrences, RDFS.domain, self.Domain))
            graph.add((self.hasOccurrences, RDFS.range, RDFS.Literal))

            # CWE Properties
            self.CWE = URIRef(self.namespace + "CWE")
            graph.add((self.CWE, RDF.type, RDFS.Class))
            # Title will be dcterms:title

            # Exploit Properties
            self.Exploit = URIRef(self.namespace + "Exploit")
            graph.add((self.Exploit, RDF.type, RDFS.Class))

            self.hasFile = URIRef(self.namespace + "hasFile")
            graph.add((self.hasFile, RDF.type, RDF.Property))
            graph.add((self.hasFile, RDFS.domain, self.Exploit))
            graph.add((self.hasFile, RDFS.range, RDFS.Literal))

            # Description will be dcterms:description

            self.affectsPlatform = URIRef(self.namespace + "affectsPlatform")
            graph.add((self.affectsPlatform, RDF.type, RDF.Property))
            graph.add((self.affectsPlatform, RDFS.domain, self.Exploit))
            graph.add((self.affectsPlatform, RDFS.range, RDFS.Literal))

            self.isType = URIRef(self.namespace + "isType")
            graph.add((self.isType, RDF.type, RDF.Property))
            graph.add((self.isType, RDFS.domain, self.Exploit))
            graph.add((self.isType, RDFS.range, RDFS.Literal))

            # CVE Properties
            self.CVE = URIRef(self.namespace + "CVE")
            graph.add((self.CVE, RDF.type, RDFS.Class))

            # Properties to link to other classes
            self.hasExploit = URIRef(self.namespace + "hasExploit")
            graph.add((self.hasExploit, RDF.type, RDF.Property))
            graph.add((self.hasExploit, RDFS.domain, self.CVE))
            graph.add((self.hasExploit, RDFS.range, self.Exploit))

            self.hasWeakness = URIRef(self.namespace + "hasWeakness")
            graph.add((self.hasWeakness, RDF.type, RDF.Property))
            graph.add((self.hasWeakness, RDFS.domain, self.CVE))
            graph.add((self.hasWeakness, RDFS.range, self.CWE))

            # Properties to describe CVE using CVSSv3 metrics

            self.hasStatus = URIRef(self.namespace + "hasStatus")
            graph.add((self.hasStatus, RDF.type, RDF.Property))
            graph.add((self.hasStatus, RDFS.domain, self.CVE))
            graph.add((self.hasStatus, RDFS.range, RDFS.Literal))

            # Description will be dcterms:description

            self.hasAttackVector = URIRef(self.namespace + "hasAttackVector")
            graph.add((self.hasAttackVector, RDF.type, RDF.Property))
            graph.add((self.hasAttackVector, RDFS.domain, self.CVE))
            graph.add((self.hasAttackVector, RDFS.range, RDFS.Literal))

            self.hasAttackComplexity = URIRef(self.namespace + "hasAttackComplexity")
            graph.add((self.hasAttackComplexity, RDF.type, RDF.Property))
            graph.add((self.hasAttackComplexity, RDFS.domain, self.CVE))
            graph.add((self.hasAttackComplexity, RDFS.range, RDFS.Literal))

            self.hasPrivilegesRequired = URIRef(self.namespace + "hasPrivilegesRequired")
            graph.add((self.hasPrivilegesRequired, RDF.type, RDF.Property))
            graph.add((self.hasPrivilegesRequired, RDFS.domain, self.CVE))
            graph.add((self.hasPrivilegesRequired, RDFS.range, RDFS.Literal))

            self.hasUserInteraction = URIRef(self.namespace + "hasUserInteraction")
            graph.add((self.hasUserInteraction, RDF.type, RDF.Property))
            graph.add((self.hasUserInteraction, RDFS.domain, self.CVE))
            graph.add((self.hasUserInteraction, RDFS.range, RDFS.Literal))

            self.hasScope = URIRef(self.namespace + "hasScope")
            graph.add((self.hasScope, RDF.type, RDF.Property))
            graph.add((self.hasScope, RDFS.domain, self.CVE))
            graph.add((self.hasScope, RDFS.range, RDFS.Literal))
            
            self.hasBaseScore = URIRef(self.namespace + "hasBaseScore")
            graph.add((self.hasBaseScore, RDF.type, RDF.Property))
            graph.add((self.hasBaseScore, RDFS.domain, self.CVE))
            graph.add((self.hasBaseScore, RDFS.range, RDFS.Literal))

            self.hasBaseSeverity = URIRef(self.namespace + "hasBaseSeverity")
            graph.add((self.hasBaseSeverity, RDF.type, RDF.Property))
            graph.add((self.hasBaseSeverity, RDFS.domain, self.CVE))
            graph.add((self.hasBaseSeverity, RDFS.range, RDFS.Literal))

            self.hasExploitabilityScore = URIRef(self.namespace + "hasExploitabilityScore")
            graph.add((self.hasExploitabilityScore, RDF.type, RDF.Property))
            graph.add((self.hasExploitabilityScore, RDFS.domain, self.CVE))
            graph.add((self.hasExploitabilityScore, RDFS.range, RDFS.Literal))

            self.hasImpactScore = URIRef(self.namespace + "hasImpactScore")
            graph.add((self.hasImpactScore, RDF.type, RDF.Property))
            graph.add((self.hasImpactScore, RDFS.domain, self.CVE))
            graph.add((self.hasImpactScore, RDFS.range, RDFS.Literal))

            self.hasConfidentialityImpact = URIRef(self.namespace + "hasConfidentialityImpact")
            graph.add((self.hasConfidentialityImpact, RDF.type, RDF.Property))
            graph.add((self.hasConfidentialityImpact, RDFS.domain, self.CVE))
            graph.add((self.hasConfidentialityImpact, RDFS.range, RDFS.Literal))

            self.hasIntegrityImpact = URIRef(self.namespace + "hasIntegrityImpact")
            graph.add((self.hasIntegrityImpact, RDF.type, RDF.Property))
            graph.add((self.hasIntegrityImpact, RDFS.domain, self.CVE))
            graph.add((self.hasIntegrityImpact, RDFS.range, RDFS.Literal))

            self.hasAvailabilityImpact = URIRef(self.namespace + "hasAvailabilityImpact")
            graph.add((self.hasAvailabilityImpact, RDF.type, RDF.Property))
            graph.add((self.hasAvailabilityImpact, RDFS.domain, self.CVE))
            graph.add((self.hasAvailabilityImpact, RDFS.range, RDFS.Literal))


            # Service Properties
            self.Service = URIRef(self.namespace + "Service")
            graph.add((self.Service, RDF.type, RDFS.Class))

            # Properties to link to other classes
            self.hasVulnerability = URIRef(self.namespace + "hasVulnerability")
            graph.add((self.hasVulnerability, RDF.type, RDF.Property))
            graph.add((self.hasVulnerability, RDFS.domain, self.Service))
            graph.add((self.hasVulnerability, RDFS.range, self.CVE))


            # IP Properties
            self.IP = URIRef(self.namespace + "IP")
            graph.add((self.IP, RDF.type, RDFS.Class))

            self.hasDomainName = URIRef(self.namespace + "hasDomainName")
            graph.add((self.hasDomainName, RDF.type, RDF.Property))
            graph.add((self.hasDomainName, RDFS.domain, self.IP))
            graph.add((self.hasDomainName, RDFS.range, self.Domain))

            # self.hasPort = URIRef(self.namespace + "hasPort")
            # graph.add((self.hasPort, RDF.type, RDF.Property))
            # graph.add((self.hasPort, RDFS.domain, self.IP))
            # graph.add((self.hasPort, RDFS.range, RDFS.Literal))

            self.hasService = URIRef(self.namespace + "hasService")
            graph.add((self.hasService, RDF.type, RDF.Property))
            graph.add((self.hasService, RDFS.domain, self.IP))
            graph.add((self.hasService, RDFS.range, self.Service))
                        
            return True
        
        except Exception as e:
            logging.error(e)
            logging.error("ERROR: Unable to create ontology properties.")
            return False

    # TODO: Add type to the list object.
    def insert_service_into_ontology(self, service: NmapPort, vulnerabilitiesList) -> URIRef:
        try:
            ns = self.namespace
            graph = self.graph
            serviceName = service.service + service.port
            serviceName = serviceName.replace(' ', '_')
            serviceNode = URIRef(ns + serviceName)

            # Check if URIRef already exists
            if not (serviceNode, None, None) in graph:
                graph.add((serviceNode, RDF.type, self.Service))
                graph.add((serviceNode, DCTERMS.title, Literal(serviceName)))
            
            for vuln in vulnerabilitiesList:
                cveNode = self.insert_cve_into_ontology(vuln= vuln.data)
                if cveNode != "":
                    graph.add((serviceNode, self.hasVulnerability, cveNode))
            
            return serviceNode

        except Exception as e:
            logging.error(e)
            logging.error("ERROR: Unable to insert CVE into ontology.")
            return ""
        
    def insert_cve_into_ontology(self, vuln: NVDVulnerability) -> URIRef:
        try:
            ns = self.namespace
            graph = self.graph
            cveNode = URIRef(ns + vuln.id)

            # Check if URIRef already exists
            if not (cveNode, None, None) in graph:
                graph.add((cveNode, RDF.type, self.CVE))
                graph.add((cveNode, DCTERMS.title, Literal(vuln.id)))

                # Add properties
                if vuln.metrics.cvss_metric_v3 != []:
                    graph.add((cveNode, self.hasStatus, Literal(vuln.vulnerability_status)))
                    description = ""
                    for desc in vuln.descriptions:
                        if desc.lang == "en":
                            description = desc.value
                    metric = vuln.metrics.cvss_metric_v3[0]
                    data = metric.data
                    graph.add((cveNode, DCTERMS.description, Literal(description)))
                    graph.add((cveNode, self.hasAttackComplexity, Literal(data.attack_complexity)))
                    graph.add((cveNode, self.hasAttackVector, Literal(data.attack_vector)))
                    graph.add((cveNode, self.hasPrivilegesRequired, Literal(data.privileges_required)))
                    graph.add((cveNode, self.hasUserInteraction, Literal(data.user_interaction)))
                    graph.add((cveNode, self.hasScope, Literal(data.scope)))
                    graph.add((cveNode, self.hasBaseScore, Literal(data.base_score)))
                    graph.add((cveNode, self.hasBaseSeverity, Literal(data.base_severity)))
                    graph.add((cveNode, self.hasExploitabilityScore, Literal(metric.exploitability_score)))
                    graph.add((cveNode, self.hasImpactScore, Literal(metric.impact_score)))
                    graph.add((cveNode, self.hasConfidentialityImpact, Literal(data.confidentiality_impact)))
                    graph.add((cveNode, self.hasIntegrityImpact, Literal(data.integrity_impact)))
                    graph.add((cveNode, self.hasAvailabilityImpact, Literal(data.availability_impact)))

                for weakness in vuln.weaknesses:
                    cweNode = self.insert_cwe_into_ontology(weakness)
                    if cweNode != "":
                        graph.add((cveNode, self.hasWeakness, cweNode))

            return cveNode
            
        except Exception as e:
            logging.error(e)
            logging.error("ERROR: Unable to insert CVE into ontology.")
            return ""
    
    def insert_cwe_into_ontology(self, weakness: NVDWeakness) -> URIRef:
        try:
            ns = self.namespace
            graph = self.graph

            for desc in weakness.descriptions:
                if desc.lang == "en":
                    description = desc.value
                    cweNode = URIRef(ns + description)
                    if not (cweNode, None, None) in graph:
                        graph.add((cweNode, RDF.type, self.CWE))
                        graph.add((cweNode, DCTERMS.title, Literal(description)))

            # cweNode = URIRef(ns + weakness.type)
            # if not (cweNode, None, None) in graph:
            #     graph.add((cweNode, RDF.type, self.CWE))
            #     graph.add((cweNode, DCTERMS.title, Literal(weakness.type)))
            #     description = ""
            #     for desc in weakness.descriptions:
            #         if desc.lang == "en":
            #             description = desc.value
            #     graph.add((cweNode, DCTERMS.description, Literal(description)))

            return cweNode

        except Exception as e:
            logging.error(e)
            logging.error("ERROR: Unable to insert CWE into ontology.")
            return ""

    def insert_domain_into_ontology(self, domain: str, occurrences: int = 1) -> URIRef:
        try:
            ns = self.namespace
            graph = self.graph
            
            domainNode = URIRef(ns + domain)
            if not (domainNode, None, None) in graph: 
                graph.add((domainNode, RDF.type, self.Domain))
                graph.add((domainNode, DCTERMS.title, Literal(domain)))
                graph.add((domainNode, self.hasOccurrences, Literal(occurrences)))
            return domainNode
        
        except Exception as e:
            logging.error(e)
            logging.error("ERROR: Unable to insert Domain into ontology.")
            return ""


    def insert_ip_into_ontology(self, host: NmapHost,) -> URIRef:
        try:
            ns = self.namespace
            graph = self.graph
            
            ipNode = URIRef(ns + host.ip)
            if not (ipNode, None, None) in graph:
                graph.add((ipNode, RDF.type, self.IP))
                graph.add((ipNode, DCTERMS.title, Literal(host.ip)))
                # add services
                for port in host.ports:
                    serviceNode = self.insert_service_into_ontology(port)
                    if serviceNode != "":
                        graph.add((ipNode, self.hasService, serviceNode))
                # add domains
                domainNode = self.insert_domain_into_ontology(domain=host.hostname)
                if domainNode != "":
                    graph.add(ipNode, self.hasDomainName, domainNode)
            return ipNode
            
        except Exception as e:
            logging.error(e)
            logging.error("ERROR: Unable to insert IP into ontology.")
            return ""




# response = collecter.query_cve("CVE-2019-2019")
# g = create_ontology("http://example.org/test#")
# print(insert_cve_into_ontology(response.vulnerabilities[0].data, g))
# g.serialize(destination='test.rdf', format='xml')

import collecter
response = collecter.query_cve("CVE-2019-2019")
b = RDFBuilder()
print(len(response.vulnerabilities[0].data.metrics.cvss_metric_v3))
# print(response.vulnerabilities[0].data.weaknesses)
print(b.insert_cve_into_ontology(response.vulnerabilities[0].data))
b.graph.serialize(destination='test2.rdf', format='xml')


# # Create new namespace
# ns = Namespace("http://www.example.org/test#")

# # Create new graph
# g = Graph()

# # Create new class
# CVE = ns.CVE
# g.add((CVE, RDF.type, RDFS.Class))

# # Create new property
# hasID = ns.hasID
# g.add((hasID, RDF.type, RDF.Property))
# g.add((hasID, RDFS.domain, CVE))
# g.add((hasID, RDFS.range, RDFS.Literal))

# # Create new instance
# CVE_2019_1234 = ns.CVE_2019_1234
# g.add((CVE_2019_1234, RDF.type, CVE))
# g.add((CVE_2019_1234, hasID, Literal("CVE-2019-1234")))

# # Print graph
# g.serialize(destination='test.rdf', formal='xml')
