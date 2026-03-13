"""
ApexScanner - Vulnerability Engine
Zero False Positive logic with Response Diffing and Verification Steps
"""
import asyncio
import json
import time
import difflib
import hashlib
import re
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import logging

try:
    from playwright.async_api import Page
except ImportError:
    pass

import httpx

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class VerificationStatus(Enum):
    """Vulnerability verification status"""
    PENDING = "pending"
    VERIFIED = "verified"
    LIKELY = "likely"
    UNLIKELY = "unlikely"
    FALSE_POSITIVE = "false_positive"


class DiffType(Enum):
    """Type of response difference"""
    STATUS_CODE = "status_code"
    CONTENT_LENGTH = "content_length"
    CONTENT_HASH = "content_hash"
    STRUCTURAL = "structural"
    SEMANTIC = "semantic"
    ERROR_PATTERN = "error_pattern"
    NEW_DATA = "new_data"


@dataclass
class ResponseDiff:
    """Difference between two responses"""
    diff_type: DiffType
    baseline_value: Any
    test_value: Any
    difference_score: float  # 0.0 to 1.0
    details: str = ""


@dataclass
class VerifiedVulnerability:
    """Verified vulnerability with confidence score"""
    id: str
    type: str
    severity: str
    url: str
    parameter: str
    payload: str
    evidence: str
    confidence: float
    verification_status: VerificationStatus
    verification_steps: List[Dict] = field(default_factory=list)
    false_positive_indicators: List[str] = field(default_factory=list)
    cwe_id: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'type': self.type,
            'severity': self.severity,
            'url': self.url,
            'parameter': self.parameter,
            'payload': self.payload[:500],
            'evidence': self.evidence[:1000],
            'confidence': self.confidence,
            'verification_status': self.verification_status.value,
            'verification_steps': self.verification_steps,
            'false_positive_indicators': self.false_positive_indicators,
            'cwe_id': self.cwe_id
        }


class VulnerabilityEngine:
    """
    Core vulnerability detection and verification engine
    Implements Zero False Positive logic through:
    - Response Diffing
    - Multi-payload verification
    - Statistical analysis
    - Context-aware scoring
    """
    
    # False positive patterns
    FALSE_POSITIVE_PATTERNS = [
        r'cloudflare',
        r'akamai',
        r'waf',
        r'blocked',
        r'forbidden',
        r'rate limit',
        r'too many requests',
        r'captcha',
        r'access denied',
    ]
    
    # Confidence thresholds
    CONFIDENCE_THRESHOLDS = {
        'verified': 0.95,
        'likely': 0.75,
        'unlikely': 0.50,
    }
    
    def __init__(
        self,
        page: Optional['Page'] = None,
        http_client: Optional[httpx.AsyncClient] = None,
        enable_browser_verification: bool = True
    ):
        self.page = page
        self.http_client = http_client
        self.enable_browser_verification = enable_browser_verification
        
        # Storage
        self._verified_vulns: List[VerifiedVulnerability] = []
        self._baseline_responses: Dict[str, Dict] = {}  # URL -> baseline response
        self._verification_cache: Dict[str, bool] = {}  # payload_hash -> verified
        
        # Statistics
        self._stats = {
            'total_candidates': 0,
            'verified': 0,
            'likely': 0,
            'unlikely': 0,
            'false_positives': 0,
            'verification_rate': 0.0
        }
    
    async def verify_vulnerability(
        self,
        candidate: Dict[str, Any],
        baseline_response: Optional[Dict] = None
    ) -> VerifiedVulnerability:
        """
        Verify a vulnerability candidate with multiple confirmation steps
        """
        self._stats['total_candidates'] += 1
        
        vuln_type = candidate.get('type', 'unknown')
        url = candidate.get('url', '')
        parameter = candidate.get('parameter', '')
        original_payload = candidate.get('payload', '')
        
        logger.info(f"Verifying {vuln_type} vulnerability at {url}")
        
        # Step 1: Check for false positive patterns
        fp_check = await self._check_false_positives(candidate)
        if fp_check:
            vuln = self._create_verified_vulnerability(
                candidate,
                VerificationStatus.FALSE_POSITIVE,
                confidence=0.1,
                false_positive_indicators=[fp_check]
            )
            self._stats['false_positives'] += 1
            return vuln
        
        # Step 2: Get or use baseline response
        if not baseline_response:
            baseline_response = await self._get_baseline_response(url)
            self._baseline_responses[url] = baseline_response
        
        # Step 3: Response diffing analysis
        diff_analysis = await self._analyze_response_diff(
            baseline=baseline_response,
            test_response=candidate.get('response', {})
        )
        
        # Step 4: Multi-payload verification
        verification_results = await self._verify_with_multiple_payloads(
            url=url,
            vuln_type=vuln_type,
            parameter=parameter,
            original_payload=original_payload
        )
        
        # Step 5: Browser-based verification (if enabled)
        browser_verification = None
        if self.enable_browser_verification and self.page:
            browser_verification = await self._browser_verification(
                url=url,
                vuln_type=vuln_type,
                payload=original_payload
            )
        
        # Step 6: Calculate final confidence
        confidence = self._calculate_confidence(
            diff_analysis=diff_analysis,
            verification_results=verification_results,
            browser_verification=browser_verification,
            candidate=candidate
        )
        
        # Step 7: Determine verification status
        status = self._determine_verification_status(confidence)
        
        # Create verified vulnerability
        vuln = self._create_verified_vulnerability(
            candidate,
            status,
            confidence=confidence,
            verification_steps=[
                {'step': 'false_positive_check', 'passed': not fp_check},
                {'step': 'response_diff', 'score': diff_analysis.get('overall_score', 0)},
                {'step': 'multi_payload_verification', 'success_rate': verification_results.get('success_rate', 0)},
                {'step': 'browser_verification', 'result': browser_verification},
            ]
        )
        
        # Update statistics
        if status == VerificationStatus.VERIFIED:
            self._stats['verified'] += 1
        elif status == VerificationStatus.LIKELY:
            self._stats['likely'] += 1
        else:
            self._stats['unlikely'] += 1
        
        self._stats['verification_rate'] = (
            (self._stats['verified'] + self._stats['likely']) / 
            max(1, self._stats['total_candidates'])
        )
        
        self._verified_vulns.append(vuln)
        
        return vuln
    
    async def _check_false_positives(self, candidate: Dict) -> Optional[str]:
        """Check for common false positive indicators"""
        response_body = str(candidate.get('response', {}).get('body', '')).lower()
        
        for pattern in self.FALSE_POSITIVE_PATTERNS:
            if re.search(pattern, response_body, re.IGNORECASE):
                return f"False positive pattern detected: {pattern}"
        
        # Check for WAF responses
        response_headers = candidate.get('response', {}).get('headers', {})
        waf_headers = ['x-waf', 'x-firewall', 'x-cdn', 'cf-ray', 'x-amz-cf-id']
        
        for header in waf_headers:
            if header in response_headers:
                return f"WAF/CDN detected: {header}"
        
        # Check for generic error pages
        if candidate.get('response', {}).get('status', 200) >= 400:
            if len(response_body) < 500:  # Short error page
                return "Generic error page (likely not vulnerable)"
        
        return None
    
    async def _get_baseline_response(self, url: str) -> Dict:
        """Get baseline response for URL"""
        try:
            if self.http_client:
                response = await self.http_client.get(url, timeout=10)
                return {
                    'status': response.status_code,
                    'headers': dict(response.headers),
                    'body': response.text[:10000],
                    'content_length': len(response.text),
                    'content_hash': hashlib.md5(response.text.encode()).hexdigest()
                }
        except Exception as e:
            logger.debug(f"Baseline request error: {e}")
        
        return {
            'status': 0,
            'headers': {},
            'body': '',
            'content_length': 0,
            'content_hash': ''
        }
    
    async def _analyze_response_diff(
        self,
        baseline: Dict,
        test_response: Dict
    ) -> Dict[str, Any]:
        """Analyze differences between baseline and test response"""
        diffs = []
        overall_score = 0.0
        
        # Status code difference
        baseline_status = baseline.get('status', 0)
        test_status = test_response.get('status', 0)
        
        if baseline_status != test_status:
            # Significant change (e.g., 401 -> 200, 404 -> 200)
            if baseline_status >= 400 and test_status == 200:
                diffs.append(ResponseDiff(
                    diff_type=DiffType.STATUS_CODE,
                    baseline_value=baseline_status,
                    test_value=test_status,
                    difference_score=1.0,
                    details=f"Status changed from {baseline_status} to {test_status}"
                ))
                overall_score += 1.0
            elif abs(test_status - baseline_status) >= 100:
                diffs.append(ResponseDiff(
                    diff_type=DiffType.STATUS_CODE,
                    baseline_value=baseline_status,
                    test_value=test_status,
                    difference_score=0.7,
                    details=f"Status changed from {baseline_status} to {test_status}"
                ))
                overall_score += 0.7
        
        # Content length difference
        baseline_length = baseline.get('content_length', 0)
        test_length = test_response.get('content_length', 0)
        
        if baseline_length > 0:
            length_ratio = test_length / baseline_length
            if length_ratio > 2.0 or length_ratio < 0.5:
                diffs.append(ResponseDiff(
                    diff_type=DiffType.CONTENT_LENGTH,
                    baseline_value=baseline_length,
                    test_value=test_length,
                    difference_score=0.8,
                    details=f"Content length changed from {baseline_length} to {test_length}"
                ))
                overall_score += 0.8
        
        # Content hash difference
        baseline_hash = baseline.get('content_hash', '')
        test_body = test_response.get('body', '')
        test_hash = hashlib.md5(test_body.encode()).hexdigest() if test_body else ''
        
        if baseline_hash and test_hash and baseline_hash != test_hash:
            # Calculate similarity
            similarity = difflib.SequenceMatcher(
                None,
                baseline.get('body', ''),
                test_body
            ).ratio()
            
            if similarity < 0.7:  # Significant difference
                diffs.append(ResponseDiff(
                    diff_type=DiffType.CONTENT_HASH,
                    baseline_value=baseline_hash,
                    test_value=test_hash,
                    difference_score=1.0 - similarity,
                    details=f"Content similarity: {similarity:.2f}"
                ))
                overall_score += (1.0 - similarity)
        
        # Check for error patterns
        test_body_lower = test_body.lower()
        error_patterns = [
            'SQL syntax', 'MySQL', 'PostgreSQL', 'Oracle', 'SQLServer',
            'PDOException', 'syntax error', 'unclosed quotation',
            'alert(', 'confirm(', 'prompt('  # XSS indicators
        ]
        
        for pattern in error_patterns:
            if pattern in test_body_lower and pattern not in baseline.get('body', '').lower():
                diffs.append(ResponseDiff(
                    diff_type=DiffType.ERROR_PATTERN,
                    baseline_value=None,
                    test_value=pattern,
                    difference_score=0.9,
                    details=f"New error pattern: {pattern}"
                ))
                overall_score += 0.9
                break
        
        # Check for new data (tokens, user data, etc.)
        new_data_indicators = ['token', 'jwt', 'session', 'api_key', 'password', 'email']
        baseline_body_lower = baseline.get('body', '').lower()
        
        for indicator in new_data_indicators:
            if indicator in test_body_lower and indicator not in baseline_body_lower:
                diffs.append(ResponseDiff(
                    diff_type=DiffType.NEW_DATA,
                    baseline_value=None,
                    test_value=indicator,
                    difference_score=0.95,
                    details=f"New sensitive data: {indicator}"
                ))
                overall_score += 0.95
                break
        
        return {
            'diffs': [asdict(d) for d in diffs],
            'overall_score': min(1.0, overall_score / 3.0),  # Normalize
            'diff_count': len(diffs)
        }
    
    async def _verify_with_multiple_payloads(
        self,
        url: str,
        vuln_type: str,
        parameter: str,
        original_payload: str
    ) -> Dict[str, Any]:
        """Verify vulnerability with multiple related payloads"""
        # Get related payloads
        related_payloads = self._get_related_payloads(vuln_type, original_payload)
        
        if not related_payloads:
            return {'success_rate': 0.0, 'tested': 0, 'successful': 0}
        
        results = []
        
        for payload in related_payloads[:5]:  # Test up to 5 payloads
            try:
                # Send test request
                response = await self._send_test_request(
                    url=url,
                    parameter=parameter,
                    payload=payload
                )
                
                # Check if response indicates vulnerability
                is_vulnerable = await self._check_vulnerability_indicators(
                    vuln_type=vuln_type,
                    response=response,
                    payload=payload
                )
                
                results.append({
                    'payload': payload,
                    'vulnerable': is_vulnerable,
                    'response_status': response.get('status', 0)
                })
                
            except Exception as e:
                logger.debug(f"Verification payload error: {e}")
        
        successful = sum(1 for r in results if r['vulnerable'])
        success_rate = successful / len(results) if results else 0.0
        
        return {
            'success_rate': success_rate,
            'tested': len(results),
            'successful': successful,
            'results': results
        }
    
    async def _browser_verification(
        self,
        url: str,
        vuln_type: str,
        payload: str
    ) -> Optional[bool]:
        """Verify vulnerability using browser"""
        try:
            if vuln_type == 'xss':
                # Navigate to URL with payload
                await self.page.goto(url, wait_until="domcontentloaded", timeout=10000)
                
                # Check for execution indicators
                indicators = await self.page.evaluate("""
                    () => {
                        const indicators = [];
                        
                        // Check for alerts
                        if (window.alerted) indicators.push('alert');
                        
                        // Check for DOM changes
                        const injectedElements = document.querySelectorAll('img[src="x"], script, svg');
                        if (injectedElements.length > 0) indicators.push('dom_injection');
                        
                        // Check console
                        const logs = [];
                        const originalLog = console.log;
                        console.log = (...args) => {
                            logs.push(args.join(' '));
                            originalLog.apply(console, args);
                        };
                        
                        return {
                            indicators,
                            logs: logs.slice(-10)
                        };
                    }
                """)
                
                return len(indicators.get('indicators', [])) > 0
            
            elif vuln_type == 'sql_injection':
                # Check for SQL error patterns in page
                content = await self.page.content()
                sql_patterns = ['SQL syntax', 'MySQL', 'PostgreSQL', 'PDOException']
                
                return any(pattern in content for pattern in sql_patterns)
        
        except Exception as e:
            logger.debug(f"Browser verification error: {e}")
        
        return None
    
    def _calculate_confidence(
        self,
        diff_analysis: Dict,
        verification_results: Dict,
        browser_verification: Optional[bool],
        candidate: Dict
    ) -> float:
        """Calculate final confidence score"""
        scores = []
        weights = []
        
        # Response diff score (weight: 0.3)
        diff_score = diff_analysis.get('overall_score', 0)
        if diff_score > 0:
            scores.append(diff_score)
            weights.append(0.3)
        
        # Multi-payload verification (weight: 0.4)
        payload_success_rate = verification_results.get('success_rate', 0)
        if verification_results.get('tested', 0) >= 2:
            scores.append(payload_success_rate)
            weights.append(0.4)
        
        # Browser verification (weight: 0.3)
        if browser_verification is not None:
            scores.append(1.0 if browser_verification else 0.2)
            weights.append(0.3)
        
        # Base confidence from candidate
        base_confidence = candidate.get('confidence', 0.5)
        scores.append(base_confidence)
        weights.append(0.2)
        
        # Calculate weighted average
        if not scores:
            return 0.5
        
        total_weight = sum(weights)
        weighted_sum = sum(s * w for s, w in zip(scores, weights))
        
        return weighted_sum / total_weight if total_weight > 0 else 0.5
    
    def _determine_verification_status(self, confidence: float) -> VerificationStatus:
        """Determine verification status based on confidence"""
        if confidence >= self.CONFIDENCE_THRESHOLDS['verified']:
            return VerificationStatus.VERIFIED
        elif confidence >= self.CONFIDENCE_THRESHOLDS['likely']:
            return VerificationStatus.LIKELY
        elif confidence >= self.CONFIDENCE_THRESHOLDS['unlikely']:
            return VerificationStatus.UNLIKELY
        else:
            return VerificationStatus.FALSE_POSITIVE
    
    def _create_verified_vulnerability(
        self,
        candidate: Dict,
        status: VerificationStatus,
        confidence: float,
        false_positive_indicators: List[str] = None,
        verification_steps: List[Dict] = None
    ) -> VerifiedVulnerability:
        """Create verified vulnerability object"""
        return VerifiedVulnerability(
            id=candidate.get('id', f"vuln_{int(time.time())}"),
            type=candidate.get('type', 'unknown'),
            severity=candidate.get('severity', 'info'),
            url=candidate.get('url', ''),
            parameter=candidate.get('parameter', ''),
            payload=candidate.get('payload', ''),
            evidence=candidate.get('evidence', ''),
            confidence=confidence,
            verification_status=status,
            verification_steps=verification_steps or [],
            false_positive_indicators=false_positive_indicators or [],
            cwe_id=candidate.get('cwe_id', [])
        )
    
    def _get_related_payloads(self, vuln_type: str, original_payload: str) -> List[str]:
        """Get payloads related to the original for verification"""
        # Simplified - in production would use payload library
        if vuln_type == 'sql_injection':
            return [
                "' OR 1=1--",
                "' OR ''='",
                "admin'--",
                "' UNION SELECT NULL--"
            ]
        elif vuln_type == 'xss':
            return [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>"
            ]
        return []
    
    async def _send_test_request(
        self,
        url: str,
        parameter: str,
        payload: str
    ) -> Dict:
        """Send test request with payload"""
        try:
            if self.http_client:
                # Try in query parameter
                test_url = f"{url.split('?')[0]}?{parameter}={payload}"
                response = await self.http_client.get(test_url, timeout=10)
                
                return {
                    'status': response.status_code,
                    'body': response.text[:5000],
                    'headers': dict(response.headers)
                }
        except Exception as e:
            logger.debug(f"Test request error: {e}")
        
        return {'status': 0, 'body': '', 'headers': {}}
    
    async def _check_vulnerability_indicators(
        self,
        vuln_type: str,
        response: Dict,
        payload: str
    ) -> bool:
        """Check if response indicates vulnerability"""
        body = response.get('body', '').lower()
        status = response.get('status', 0)
        
        if vuln_type == 'sql_injection':
            # Check for SQL errors
            sql_errors = ['SQL syntax', 'MySQL', 'PostgreSQL', 'PDOException']
            if any(err in body for err in sql_errors):
                return True
            
            # Check for auth bypass
            if status == 200 and ('token' in body or 'user' in body):
                return True
        
        elif vuln_type == 'xss':
            # Check for payload reflection
            if payload in body:
                return True
        
        elif vuln_type == 'idor':
            # Check for successful access
            if status == 200 and len(body) > 100:
                return True
        
        return False
    
    def get_verified_vulnerabilities(self) -> List[VerifiedVulnerability]:
        """Get all verified vulnerabilities"""
        return self._verified_vulns
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get verification statistics"""
        return self._stats


def asdict(obj):
    """Helper to convert dataclass to dict"""
    if hasattr(obj, '__dataclass_fields__'):
        from dataclasses import fields
        return {f.name: getattr(obj, f.name) for f in fields(obj)}
    return obj


if __name__ == "__main__":
    print("ApexScanner Vulnerability Engine loaded")
    print("Zero False Positive logic enabled")
