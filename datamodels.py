"""
This file contains the data models for the NVD API and the Nmap XML output format.
"""

from pydantic import BaseModel, Field, validator
from datetime import datetime
from typing import List, Optional

def datetime_parser(value):
    # Parse format YYYY-MM-DDTHH:MM:SS.SSS
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%f')

class BaseConfig:    
    json_encoders = {
        datetime: datetime_parser
    }

class NVDVulnerabilityDescription(BaseModel):    
    lang: str = Field(..., alias="lang")
    value: str = Field(..., alias="value")

class NVDWeakness(BaseModel):
    source: str = Field(..., alias="source")
    type: str = Field(..., alias="type")
    descriptions: List[NVDVulnerabilityDescription] = Field(..., alias="description")

class NVDReference(BaseModel):
    url: str = Field(..., alias="url")
    source: str = Field(..., alias="source")
    tags: Optional[List[str]] = Field([], alias="tags")

class CVSSMetricBase(BaseModel):
    source: str = Field(..., alias="source")
    type: str = Field(..., alias="type")
    exploitability_score: float = Field(..., alias="exploitabilityScore")
    impact_score: float = Field(..., alias="impactScore")

class CVSSMetricDataBase(BaseModel):
    version: str = Field(..., alias="version")
    vector_string: str = Field(..., alias="vectorString")
    base_score: float = Field(..., alias="baseScore")
    confidentiality_impact: str = Field(..., alias="confidentialityImpact")
    integrity_impact: str = Field(..., alias="integrityImpact")
    availability_impact: str = Field(..., alias="availabilityImpact")

class CVSSMetricV3Data(CVSSMetricDataBase):
    attack_vector: str = Field(..., alias="attackVector")
    attack_complexity: str = Field(..., alias="attackComplexity")
    privileges_required: str = Field(..., alias="privilegesRequired")
    user_interaction: str = Field(..., alias="userInteraction")
    scope: str = Field(..., alias="scope")
    base_severity: str = Field(..., alias="baseSeverity")

class CVSSMetricV3(CVSSMetricBase):
    data: CVSSMetricV3Data = Field(..., alias="cvssData")

class CVSSMetricV2Data(CVSSMetricDataBase):
    access_vector: str = Field(..., alias="accessVector")
    access_complexity: str = Field(..., alias="accessComplexity")
    authentication: str = Field(..., alias="authentication")

class CVSSMetricV2(CVSSMetricBase):
    data: CVSSMetricV2Data = Field(..., alias="cvssData")
    base_severity: str = Field(..., alias="baseSeverity")
    ac_insuf_info: bool = Field(..., alias="acInsufInfo")
    obtain_all_privilege: bool = Field(..., alias="obtainAllPrivilege")
    obtain_user_privilege: bool = Field(..., alias="obtainUserPrivilege")
    obtain_other_privilege: bool = Field(..., alias="obtainOtherPrivilege")
    user_interaction_required: bool = Field(False, alias="userInteractionRequired")


class NVDMetrics(BaseModel):
    cvss_metric_v3: Optional[List[CVSSMetricV3]] = Field([], alias="cvssMetricV30")
    cvss_metric_v2: Optional[List[CVSSMetricV2]] = Field([], alias="cvssMetricV2")

class NVDVulnerability(BaseModel):
    id: str = Field(..., alias="id")
    source_identifier: str = Field(..., alias="sourceIdentifier")
    published: datetime = Field(..., alias="published")
    last_modified: datetime = Field(..., alias="lastModified")
    vulnerability_status: str = Field(..., alias="vulnStatus")
    descriptions: List[NVDVulnerabilityDescription] = Field(..., alias="descriptions")
    metrics: NVDMetrics = Field(..., alias="metrics")
    weaknesses: Optional[List[NVDWeakness]] = Field([], alias="weaknesses")
    references: List[NVDReference] = Field(..., alias="references")

    class Config(BaseConfig):
        pass

class NVDVulnerabilityWrapper(BaseModel):
    data: NVDVulnerability = Field(..., alias="cve")

class NVDResponse(BaseModel):
    results_per_page: int = Field(..., alias='resultsPerPage')
    start_index: int = Field(..., alias='startIndex')
    total_results: int = Field(..., alias='totalResults')
    format: str = Field(..., alias='format')
    version: str = Field(..., alias='version')
    timestamp: datetime = Field(..., alias='timestamp')
    vulnerabilities: List[NVDVulnerabilityWrapper] = Field(..., alias='vulnerabilities')

    class Config(BaseConfig):
        pass

    def __str__(self) -> str:
        return f"Total results: {self.total_results}, timestamp: {self.timestamp}"