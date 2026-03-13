"""
BOLA/IDOR Tester
Broken Object Level Authorization / Insecure Direct Object Reference detection
Uses dual-session comparison, token swapping, and authorization bypass techniques
"""
import asyncio
import time
import json
import re
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import logging
from urllib.parse import urlparse, parse_qs, urljoin

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class BOLASeverity(Enum):
    """BOLA vulnerability severity"""
    CRITICAL = "critical"  # Direct access to sensitive data (payments, passwords)
    HIGH = "high"  # Access to user data (profiles, orders)
    MEDIUM = "medium"  # Limited data exposure
    LOW = "low"  # Minimal impact
    INFO = "info"  # Potential issue, needs verification


@dataclass
class BOLAFinding:
    """BOLA/IDOR vulnerability finding"""
    severity: BOLASeverity
    url: str
    method: str
    parameter: str
    user_a_data: Dict[str, Any]
    user_b_data: Dict[str, Any]
    vulnerability_type: str
    evidence: str
    exploited: bool = False  # Was data actually accessed
    data_exposed: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "template-id": f"bola-{self.vulnerability_type.lower().replace(' ', '-')}",
            "tool": "bola-idor-tester",
            "info": {
                "name": f"BOLA/IDOR: {self.vulnerability_type}",
                "description": f"Insecure Direct Object Reference detected. {self.evidence}",
                "severity": self.severity.value,
                "solution": "Implement proper authorization checks. Use indirect object references. Validate user ownership.",
                "cwe-id": ["CWE-639", "CWE-284"],
                "references": []
            },
            "url": self.url,
            "matched-at": self.url,
            "parameter": self.parameter,
            "evidence": self.evidence[:500],
            "user_a": self.user_a_data.get('email', 'unknown'),
            "user_b": self.user_b_data.get('email', 'unknown'),
            "exploited": self.exploited
        }


@dataclass
class EndpointInfo:
    """Endpoint information for BOLA testing"""
    url: str
    method: str
    parameters: Dict[str, str]
    auth_required: bool = False
    resource_type: str = ""  # user, order, payment, address, etc.
    id_parameter: Optional[str] = None  # Parameter containing resource ID


class BOLATester:
    """
    BOLA/IDOR vulnerability tester
    Tests for unauthorized access to resources using different user sessions
    """

    def __init__(
        self,
        session_a_headers: Dict[str, str],
        session_b_headers: Dict[str, str],
        session_a_info: Dict[str, Any],
        session_b_info: Dict[str, Any],
        timeout: int = 30
    ):
        self.session_a_headers = session_a_headers
        self.session_b_headers = session_b_headers
        self.session_a_info = session_a_info  # {user_id, email, role, etc.}
        self.session_b_info = session_b_info

        self.timeout = timeout
        self.findings: List[BOLAFinding] = []

        self._http_session = requests.Session()
        self._http_session.verify = False
        self._http_session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
        })

        # Common IDOR parameter names
        self.id_parameters = [
            'id', 'user_id', 'userid', 'uid', 'account_id',
            'order_id', 'orderid', 'oid',
            'payment_id', 'paymentid', 'pid',
            'address_id', 'addressid', 'aid',
            'profile_id', 'profileid',
            'document_id', 'documentid', 'did',
            'file_id', 'fileid', 'fid',
            'item_id', 'itemid', 'iid',
            'product_id', 'productid',
            'cart_id', 'cartid', 'cid',
            'session_id', 'sessionid', 'sid',
            'token', 'key', 'ref', 'reference'
        ]

        # Sensitive data patterns
        self.sensitive_patterns = [
            r'password', r'passwd', r'pwd',
            r'credit.?card', r'card.?number', r'cvv', r'cvc',
            r'social.?security', r'ssn',
            r'bank.?account', r'account.?number',
            r'api.?key', r'apikey', r'access.?token',
            r'private.?key', r'secret'
        ]

    def test_endpoint(
        self,
        endpoint: EndpointInfo
    ) -> List[BOLAFinding]:
        """
        Test single endpoint for BOLA/IDOR vulnerabilities
        """
        findings = []

        logger.info(f"Testing BOLA on {endpoint.method} {endpoint.url}")

        # Test 1: Direct ID substitution
        if endpoint.id_parameter:
            finding = self._test_id_substitution(endpoint)
            if finding:
                findings.append(finding)

        # Test 2: Token swapping
        finding = self._test_token_swapping(endpoint)
        if finding:
            findings.append(finding)

        # Test 3: Parameter manipulation
        findings.extend(self._test_parameter_manipulation(endpoint))

        # Test 4: Mass assignment / Parameter pollution
        finding = self._test_mass_assignment(endpoint)
        if finding:
            findings.append(finding)

        self.findings.extend(findings)
        return findings

    def _test_id_substitution(self, endpoint: EndpointInfo) -> Optional[BOLAFinding]:
        """
        Test BOLA by substituting resource IDs
        User A tries to access User B's resources
        """
        try:
            user_a_id = self.session_a_info.get('user_id')
            user_b_id = self.session_b_info.get('user_id')

            if not user_a_id or not user_b_id:
                return None

            id_param = endpoint.id_parameter

            # Request with User A's session, accessing User B's resource
            url_a = self._replace_id(endpoint.url, id_param, user_b_id)

            resp_a = self._http_session.request(
                endpoint.method,
                url_a,
                headers=self.session_a_headers,
                timeout=self.timeout,
                verify=False
            )

            # Request with User B's session, accessing own resource
            url_b = self._replace_id(endpoint.url, id_param, user_b_id)

            resp_b = self._http_session.request(
                endpoint.method,
                url_b,
                headers=self.session_b_headers,
                timeout=self.timeout,
                verify=False
            )

            # Analyze responses
            if self._is_bola_vulnerable(resp_a, resp_b, user_b_id):
                severity = self._assess_severity(resp_a, endpoint.resource_type)

                finding = BOLAFinding(
                    severity=severity,
                    url=url_a,
                    method=endpoint.method,
                    parameter=id_param,
                    user_a_data={
                        'email': self.session_a_info.get('email'),
                        'status_code': resp_a.status_code
                    },
                    user_b_data={
                        'email': self.session_b_info.get('email'),
                        'status_code': resp_b.status_code
                    },
                    vulnerability_type="ID Substitution",
                    evidence=f"User A accessed User B's {endpoint.resource_type or 'resource'} (ID: {user_b_id})",
                    exploited=resp_a.status_code == 200,
                    data_exposed=resp_a.text[:500] if resp_a.status_code == 200 else None
                )

                logger.warning(f"BOLA found via ID substitution: {url_a}")
                return finding

        except Exception as e:
            logger.debug(f"ID substitution test error: {e}")

        return None

    def _test_token_swapping(self, endpoint: EndpointInfo) -> Optional[BOLAFinding]:
        """
        Test BOLA by swapping auth tokens between requests
        """
        try:
            # Get original request with User A's session
            resp_a = self._http_session.request(
                endpoint.method,
                endpoint.url,
                headers=self.session_a_headers,
                timeout=self.timeout,
                verify=False
            )

            # Swap token - use User A's token with User B's other headers
            modified_headers = self.session_b_headers.copy()

            # Extract and swap authorization header
            auth_header = self.session_a_headers.get('Authorization')
            if auth_header:
                modified_headers['Authorization'] = auth_header

            resp_swapped = self._http_session.request(
                endpoint.method,
                endpoint.url,
                headers=modified_headers,
                timeout=self.timeout,
                verify=False
            )

            # If swapped request succeeds with User A's data - BOLA
            if resp_swapped.status_code == 200:
                try:
                    data = resp_swapped.json()
                    user_a_id = self.session_a_info.get('user_id')

                    # Check if response contains User A's data
                    if self._contains_user_data(data, user_a_id):
                        finding = BOLAFinding(
                            severity=BOLASeverity.HIGH,
                            url=endpoint.url,
                            method=endpoint.method,
                            parameter="Authorization",
                            user_a_data={'email': self.session_a_info.get('email')},
                            user_b_data={'email': self.session_b_info.get('email')},
                            vulnerability_type="Token Swapping",
                            evidence="Authorization token can be swapped between users",
                            exploited=True
                        )
                        logger.warning(f"BOLA found via token swapping: {endpoint.url}")
                        return finding

                except json.JSONDecodeError:
                    pass

        except Exception as e:
            logger.debug(f"Token swapping test error: {e}")

        return None

    def _test_parameter_manipulation(self, endpoint: EndpointInfo) -> List[BOLAFinding]:
        """
        Test BOLA by manipulating various parameters
        """
        findings = []

        user_a_id = self.session_a_info.get('user_id')
        user_b_id = self.session_b_info.get('user_id')

        if not user_a_id or not user_b_id:
            return findings

        # Try common IDOR parameters
        for param in self.id_parameters:
            try:
                # Build URL with User B's ID
                test_url = endpoint.url

                if '?' in test_url:
                    test_url = f"{test_url}&{param}={user_b_id}"
                else:
                    test_url = f"{test_url}?{param}={user_b_id}"

                resp = self._http_session.request(
                    endpoint.method,
                    test_url,
                    headers=self.session_a_headers,
                    timeout=self.timeout,
                    verify=False
                )

                if resp.status_code == 200:
                    try:
                        data = resp.json()

                        # Check if we got User B's data
                        if self._contains_user_data(data, user_b_id):
                            severity = self._assess_severity(resp, endpoint.resource_type)

                            finding = BOLAFinding(
                                severity=severity,
                                url=test_url,
                                method=endpoint.method,
                                parameter=param,
                                user_a_data={'email': self.session_a_info.get('email')},
                                user_b_data={'email': self.session_b_info.get('email')},
                                vulnerability_type="Parameter Manipulation",
                                evidence=f"Parameter '{param}' allows unauthorized access",
                                exploited=True,
                                data_exposed=str(data)[:300]
                            )
                            findings.append(finding)
                            logger.warning(f"BOLA found via parameter {param}: {test_url}")

                    except json.JSONDecodeError:
                        pass

            except Exception as e:
                logger.debug(f"Parameter manipulation error: {e}")

        return findings

    def _test_mass_assignment(self, endpoint: EndpointInfo) -> Optional[BOLAFinding]:
        """
        Test for mass assignment / parameter pollution
        User tries to update resource with additional privileged parameters
        """
        if endpoint.method not in ['POST', 'PUT', 'PATCH']:
            return None

        try:
            # Base payload
            base_payload = {'test_field': 'test_value'}

            # Privileged parameters to inject
            privileged_params = {
                'user_id': self.session_b_info.get('user_id'),
                'is_admin': True,
                'role': 'admin',
                'price': 0.01,
                'discount': 100,
                'approved': True
            }

            # Test with privileged params
            privileged_payload = {**base_payload, **privileged_params}

            resp_base = self._http_session.request(
                endpoint.method,
                endpoint.url,
                headers=self.session_a_headers,
                json=base_payload,
                timeout=self.timeout,
                verify=False
            )

            resp_priv = self._http_session.request(
                endpoint.method,
                endpoint.url,
                headers=self.session_a_headers,
                json=privileged_payload,
                timeout=self.timeout,
                verify=False
            )

            # Check if privileged params were accepted
            if resp_priv.status_code == 200 or resp_priv.status_code < resp_base.status_code:
                try:
                    data_priv = resp_priv.json()
                    data_base = resp_base.json()

                    # If responses differ and privileged was accepted
                    if data_priv != data_base:
                        finding = BOLAFinding(
                            severity=BOLASeverity.MEDIUM,
                            url=endpoint.url,
                            method=endpoint.method,
                            parameter="body",
                            user_a_data={'email': self.session_a_info.get('email')},
                            user_b_data={},
                            vulnerability_type="Mass Assignment",
                            evidence="Server accepts privileged parameters",
                            exploited=True
                        )
                        logger.warning(f"Mass assignment vulnerability: {endpoint.url}")
                        return finding

                except json.JSONDecodeError:
                    pass

        except Exception as e:
            logger.debug(f"Mass assignment test error: {e}")

        return None

    def _replace_id(self, url: str, param: str, new_id: str) -> str:
        """Replace ID in URL"""
        # Try to replace in path
        import re
        pattern = rf'({param}[=/])(\d+|[a-fA-F0-9-]+)'
        return re.sub(pattern, rf'\1{new_id}', url, count=1)

    def _is_bola_vulnerable(
        self,
        resp_a: requests.Response,
        resp_b: requests.Response,
        target_id: str
    ) -> bool:
        """
        Determine if BOLA vulnerability exists
        Compare responses from User A and User B
        """
        # Both succeeded - potential BOLA
        if resp_a.status_code == 200 and resp_b.status_code == 200:
            try:
                data_a = resp_a.json()
                data_b = resp_b.json()

                # Check if User A got User B's data
                if self._contains_user_data(data_a, target_id):
                    return True

                # Identical responses for user-specific resource
                if data_a == data_b:
                    return True

            except json.JSONDecodeError:
                # Non-JSON - check content similarity
                if len(resp_a.text) > 100 and len(resp_b.text) > 100:
                    similarity = self._string_similarity(resp_a.text, resp_b.text)
                    if similarity > 0.9:
                        return True

        # User A succeeded, User B got error - proper auth (not vulnerable)
        if resp_a.status_code == 200 and resp_b.status_code in [401, 403, 404]:
            return False

        return False

    def _contains_user_data(self, data: Any, user_id: str) -> bool:
        """Check if data contains specific user's information"""
        if not data:
            return False

        data_str = json.dumps(data)

        # Check for user ID
        if str(user_id) in data_str:
            return True

        # Check for common user data fields
        user_fields = ['userId', 'user_id', 'ownerId', 'owner_id', 'accountId', 'account_id']
        for field in user_fields:
            try:
                if isinstance(data, dict):
                    if data.get(field) == user_id:
                        return True
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and item.get(field) == user_id:
                            return True
            except:
                pass

        return False

    def _assess_severity(self, response: requests.Response, resource_type: str) -> BOLASeverity:
        """Assess severity based on exposed data"""
        try:
            data = response.json()
            data_str = json.dumps(data).lower()

            # Check for sensitive data
            for pattern in self.sensitive_patterns:
                if re.search(pattern, data_str):
                    return BOLASeverity.CRITICAL

            # Resource type based severity
            critical_resources = ['payment', 'credit', 'bank', 'password', 'secret', 'key']
            high_resources = ['user', 'profile', 'order', 'address', 'document', 'file']

            if resource_type:
                resource_lower = resource_type.lower()
                if any(r in resource_lower for r in critical_resources):
                    return BOLASeverity.CRITICAL
                elif any(r in resource_lower for r in high_resources):
                    return BOLASeverity.HIGH

            # Default
            return BOLASeverity.MEDIUM

        except:
            return BOLASeverity.MEDIUM

    def _string_similarity(self, s1: str, s2: str) -> float:
        """Calculate string similarity ratio"""
        if len(s1) != len(s2):
            # Length-based similarity
            return min(len(s1), len(s2)) / max(len(s1), len(s2))
        if s1 == s2:
            return 1.0

        matches = sum(c1 == c2 for c1, c2 in zip(s1, s2))
        return matches / len(s1)

    def get_findings(self) -> List[BOLAFinding]:
        """Get all findings"""
        return self.findings

    def get_findings_summary(self) -> Dict[str, Any]:
        """Get summary of findings"""
        return {
            'total': len(self.findings),
            'exploited': len([f for f in self.findings if f.exploited]),
            'by_severity': {s.value: len([f for f in self.findings if f.severity == s]) for s in BOLASeverity},
            'by_type': {}
        }


class BOLAEndpointScanner:
    """
    Scanner to discover and test endpoints for BOLA
    """

    def __init__(self, tester: BOLATester):
        self.tester = tester
        self.endpoints: List[EndpointInfo] = []

    def extract_endpoints_from_traffic(
        self,
        requests: List[Any],
        responses: List[Any]
    ) -> List[EndpointInfo]:
        """
        Extract potential BOLA endpoints from captured traffic
        """
        endpoints = []
        seen_urls: Set[str] = set()

        for req, resp in zip(requests, responses):
            try:
                url = req.url
                if url in seen_urls:
                    continue

                # Skip static resources
                if self._is_static_resource(url):
                    continue

                # Parse URL for ID patterns
                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                # Look for ID patterns in path
                path_parts = parsed.path.split('/')
                id_param = None
                resource_type = ""

                for i, part in enumerate(path_parts):
                    if part.isdigit() or self._looks_like_id(part):
                        id_param = 'id'
                        if i > 0:
                            resource_type = path_parts[i - 1]
                        break

                # Check query params for IDs
                for param, values in params.items():
                    if param.lower() in self.tester.id_parameters:
                        id_param = param
                        break

                # Only include if looks like resource endpoint
                if id_param or resource_type:
                    endpoint = EndpointInfo(
                        url=url,
                        method=req.method,
                        parameters=params,
                        auth_required=bool(req.headers.get('Authorization')),
                        resource_type=resource_type,
                        id_parameter=id_param
                    )
                    endpoints.append(endpoint)
                    seen_urls.add(url)

            except Exception as e:
                logger.debug(f"Endpoint extraction error: {e}")

        self.endpoints.extend(endpoints)
        return endpoints

    def _is_static_resource(self, url: str) -> bool:
        """Check if URL is a static resource"""
        static_extensions = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.map']
        return any(url.lower().endswith(ext) for ext in static_extensions)

    def _looks_like_id(self, value: str) -> bool:
        """Check if value looks like an ID"""
        if not value:
            return False

        # UUID pattern
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        if re.match(uuid_pattern, value.lower()):
            return True

        # Numeric ID
        if value.isdigit():
            return True

        # Base64-like ID
        if re.match(r'^[A-Za-z0-9_-]{16,}$', value):
            return True

        return False

    def scan_all_endpoints(self) -> List[BOLAFinding]:
        """Test all extracted endpoints for BOLA"""
        all_findings = []

        for endpoint in self.endpoints:
            findings = self.tester.test_endpoint(endpoint)
            all_findings.extend(findings)

        return all_findings


if __name__ == "__main__":
    print("BOLA/IDOR Tester module loaded")
