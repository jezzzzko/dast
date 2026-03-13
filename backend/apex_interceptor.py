"""
ApexScanner - Core Interception Module
Action-Interception-Mutation Architecture
High-performance request/response capture with real-time queue management
"""
import asyncio
import json
import time
import hashlib
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import deque
from urllib.parse import urlparse, parse_qs, unquote
import logging
import re

try:
    from playwright.async_api import Page, Request, Response
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class RequestType(Enum):
    """Request classification"""
    XHR = "xhr"
    FETCH = "fetch"
    WEBSOCKET = "websocket"
    EVENTSOURCE = "eventsource"
    SCRIPT = "script"
    STYLESHEET = "stylesheet"
    IMAGE = "image"
    FONT = "font"
    OTHER = "other"


class SensitivityLevel(Enum):
    """Request sensitivity for prioritization"""
    CRITICAL = "critical"  # Auth, login, token endpoints
    HIGH = "high"  # User data, API mutations
    MEDIUM = "medium"  # Standard API calls
    LOW = "low"  # Static resources, info endpoints


@dataclass
class CapturedRequest:
    """Intercepted request data"""
    id: str
    url: str
    method: str
    headers: Dict[str, str]
    body: Optional[str]
    body_json: Optional[Dict]
    resource_type: RequestType
    timestamp: float
    sensitivity: SensitivityLevel = SensitivityLevel.MEDIUM
    
    # Parsed components
    path: str = ""
    query_params: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    auth_token: Optional[str] = None
    content_type: str = ""
    
    def __post_init__(self):
        """Parse URL and extract components"""
        try:
            parsed = urlparse(self.url)
            self.path = parsed.path
            self.query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}
            
            # Extract auth token
            auth_header = self.headers.get('authorization', '')
            if auth_header.startswith('Bearer '):
                self.auth_token = auth_header[7:]
            
            # Extract cookies
            cookie_header = self.headers.get('cookie', '')
            if cookie_header:
                for cookie in cookie_header.split(';'):
                    if '=' in cookie:
                        k, v = cookie.split('=', 1)
                        self.cookies[k.strip()] = v.strip()
            
            # Determine content type
            self.content_type = self.headers.get('content-type', '')
            
            # Classify sensitivity
            self._classify_sensitivity()
            
        except Exception as e:
            logger.debug(f"Request parsing error: {e}")
    
    def _classify_sensitivity(self):
        """Classify request sensitivity based on URL and method"""
        url_lower = self.url.lower()
        path_lower = self.path.lower()
        
        # Critical: Auth endpoints
        if any(x in url_lower for x in ['login', 'auth', 'token', 'session', 'oauth', 'jwt']):
            self.sensitivity = SensitivityLevel.CRITICAL
            return
        
        # High: User data, mutations
        if any(x in url_lower for x in ['user', 'account', 'profile', 'password', 'email']):
            self.sensitivity = SensitivityLevel.HIGH
            return
        
        if self.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            self.sensitivity = SensitivityLevel.HIGH
            return
        
        # Medium: Standard API
        if '/api/' in url_lower or '/rest/' in url_lower:
            self.sensitivity = SensitivityLevel.MEDIUM
            return
        
        # Low: Static resources
        self.sensitivity = SensitivityLevel.LOW
    
    def to_fuzzing_input(self) -> Dict[str, Any]:
        """Convert to format suitable for fuzzing"""
        return {
            'id': self.id,
            'url': self.url,
            'method': self.method,
            'path': self.path,
            'query_params': self.query_params,
            'headers': self.headers,
            'body_json': self.body_json,
            'body': self.body,
            'content_type': self.content_type,
            'auth_token': self.auth_token,
            'cookies': self.cookies
        }


@dataclass
class CapturedResponse:
    """Intercepted response data"""
    request_id: str
    url: str
    status: int
    headers: Dict[str, str]
    body: Optional[str]
    body_json: Optional[Dict]
    response_time_ms: float
    timestamp: float
    
    # Analysis
    content_length: int = 0
    content_type: str = ""
    has_error: bool = False
    error_patterns: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Analyze response"""
        try:
            self.content_length = len(self.body) if self.body else 0
            self.content_type = self.headers.get('content-type', '')
            
            # Check for error indicators
            if self.status >= 400:
                self.has_error = True
            
            # Check for SQL errors
            if self.body:
                sql_error_patterns = [
                    r'SQL syntax.*MySQL', r'PostgreSQL.*ERROR', r'ORA-\d+',
                    r'SQLServer.*Error', r'SQLite.*Error', r'PDOException'
                ]
                for pattern in sql_error_patterns:
                    if re.search(pattern, self.body, re.IGNORECASE):
                        self.error_patterns.append(pattern)
                        self.has_error = True
                        
        except Exception as e:
            logger.debug(f"Response analysis error: {e}")
    
    def get_content_hash(self) -> str:
        """Get hash of response body for comparison"""
        if not self.body:
            return hashlib.md5(b'').hexdigest()
        return hashlib.md5(self.body.encode('utf-8', errors='ignore')).hexdigest()


@dataclass
class RequestResponsePair:
    """Paired request and response"""
    request: CapturedRequest
    response: CapturedResponse
    fuzzing_results: List[Dict] = field(default_factory=list)
    vulnerability_score: float = 0.0


class RequestInterceptor:
    """
    High-performance request/response interceptor
    Captures, analyzes, and queues requests for fuzzing
    """
    
    def __init__(
        self,
        page: Optional['Page'] = None,
        max_queue_size: int = 1000,
        enable_body_capture: bool = True,
        filter_static: bool = True
    ):
        self.page = page
        self.max_queue_size = max_queue_size
        self.enable_body_capture = enable_body_capture
        self.filter_static = filter_static
        
        # Storage
        self._requests: Dict[str, CapturedRequest] = {}
        self._responses: Dict[str, CapturedResponse] = {}
        self._pairs: Dict[str, RequestResponsePair] = {}
        
        # Queue for fuzzing (priority-based)
        self._fuzz_queue: deque = deque(maxlen=max_queue_size)
        self._critical_queue: deque = deque(maxlen=100)
        self._high_queue: deque = deque(maxlen=300)
        
        # Statistics
        self._stats = {
            'total_requests': 0,
            'total_responses': 0,
            'critical_requests': 0,
            'high_priority_requests': 0,
            'queued_for_fuzzing': 0
        }
        
        # Callbacks
        self._on_request_callback: Optional[Callable] = None
        self._on_response_callback: Optional[Callable] = None
        self._on_pair_complete: Optional[Callable] = None
        
        # Route handlers
        self._route_handlers = []
        
        # Request ID counter
        self._request_counter = 0

    async def attach(self, page: 'Page'):
        """Attach interceptor to page"""
        self.page = page

        # Setup request interception
        await page.route("**/*", self._handle_request)

        # Setup response capture with decorator
        @page.on("response")
        def on_response(response):
            asyncio.create_task(self._handle_response(response))

        logger.info("RequestInterceptor attached to page")
    
    async def _handle_request(self, route: 'Route'):
        """Handle intercepted request"""
        request = route.request
        
        # Skip static resources if filtering enabled
        if self.filter_static:
            resource_type = request.resource_type
            if resource_type in ['image', 'font', 'stylesheet', 'websocket']:
                await route.continue_()
                return
        
        # Capture request
        start_time = time.time()
        
        try:
            request_id = f"req_{self._request_counter}"
            self._request_counter += 1
            
            # Extract headers
            headers = {k: str(v) for k, v in request.headers.items()}
            
            # Extract body
            body = None
            body_json = None
            
            if self.enable_body_capture and request.method in ['POST', 'PUT', 'PATCH']:
                try:
                    post_data = request.post_data
                    if post_data:
                        body = post_data
                        # Try to parse JSON
                        if 'application/json' in headers.get('content-type', ''):
                            try:
                                body_json = json.loads(post_data)
                            except:
                                pass
                except Exception as e:
                    logger.debug(f"Failed to capture request body: {e}")
            
            # Create captured request
            captured = CapturedRequest(
                id=request_id,
                url=request.url,
                method=request.method,
                headers=headers,
                body=body,
                body_json=body_json,
                resource_type=RequestType(request.resource_type) if request.resource_type in [e.value for e in RequestType] else RequestType.OTHER,
                timestamp=start_time
            )
            
            # Store
            self._requests[request_id] = captured
            self._stats['total_requests'] += 1
            
            # Update sensitivity stats
            if captured.sensitivity == SensitivityLevel.CRITICAL:
                self._stats['critical_requests'] += 1
            elif captured.sensitivity == SensitivityLevel.HIGH:
                self._stats['high_priority_requests'] += 1
            
            # Queue for fuzzing (skip static resources)
            if captured.resource_type in [RequestType.XHR, RequestType.FETCH, RequestType.OTHER]:
                if captured.sensitivity == SensitivityLevel.CRITICAL:
                    self._critical_queue.append(captured)
                elif captured.sensitivity == SensitivityLevel.HIGH:
                    self._high_queue.append(captured)
                else:
                    self._fuzz_queue.append(captured)
                
                self._stats['queued_for_fuzzing'] += 1
                
                # Notify callback
                if self._on_request_callback:
                    await self._on_request_callback(captured)
            
            logger.debug(f"Captured request: {captured.method} {captured.path}")
            
        except Exception as e:
            logger.error(f"Request capture error: {e}")
        
        # Continue request
        await route.continue_()
    
    async def _handle_response(self, response: 'Response'):
        """Handle response"""
        try:
            start_time = time.time()
            
            # Find matching request (by URL - simplified matching)
            matching_request = None
            for req_id, req in self._requests.items():
                if req.url == response.url and req_id not in self._pairs:
                    matching_request = req
                    break
            
            if not matching_request:
                return
            
            # Capture response body
            body = None
            body_json = None
            
            if self.enable_body_capture:
                try:
                    body = await response.text()
                    if 'application/json' in response.headers.get('content-type', ''):
                        try:
                            body_json = json.loads(body)
                        except:
                            pass
                except Exception as e:
                    logger.debug(f"Failed to capture response body: {e}")
            
            # Calculate response time
            response_time = (time.time() - start_time) * 1000
            
            # Create captured response
            captured = CapturedResponse(
                request_id=matching_request.id,
                url=response.url,
                status=response.status,
                headers={k: str(v) for k, v in response.headers.items()},
                body=body[:50000] if body else None,  # Limit size
                body_json=body_json,
                response_time_ms=response_time,
                timestamp=time.time()
            )
            
            # Store
            self._responses[matching_request.id] = captured
            self._stats['total_responses'] += 1
            
            # Create pair
            pair = RequestResponsePair(
                request=matching_request,
                response=captured
            )
            self._pairs[matching_request.id] = pair
            
            # Notify callback
            if self._on_pair_complete:
                await self._on_pair_complete(pair)
            
            logger.debug(f"Captured response: {response.status} {response.url}")
            
        except Exception as e:
            logger.error(f"Response capture error: {e}")
    
    def get_next_for_fuzzing(self, priority: str = 'critical') -> Optional[CapturedRequest]:
        """Get next request from fuzzing queue"""
        if priority == 'critical' and self._critical_queue:
            return self._critical_queue.popleft()
        elif priority == 'high' and self._high_queue:
            return self._high_queue.popleft()
        elif self._fuzz_queue:
            return self._fuzz_queue.popleft()
        return None
    
    def get_all_pairs(self) -> List[RequestResponsePair]:
        """Get all captured request-response pairs"""
        return list(self._pairs.values())
    
    def get_pairs_by_sensitivity(self, sensitivity: SensitivityLevel) -> List[RequestResponsePair]:
        """Get pairs filtered by sensitivity"""
        return [p for p in self._pairs.values() if p.request.sensitivity == sensitivity]
    
    def get_pairs_with_errors(self) -> List[RequestResponsePair]:
        """Get pairs where response has errors"""
        return [p for p in self._pairs.values() if p.response.has_error]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get interceptor statistics"""
        return {
            **self._stats,
            'pending_fuzzing': len(self._fuzz_queue) + len(self._critical_queue) + len(self._high_queue),
            'captured_pairs': len(self._pairs)
        }
    
    def clear(self):
        """Clear all captured data"""
        self._requests.clear()
        self._responses.clear()
        self._pairs.clear()
        self._fuzz_queue.clear()
        self._critical_queue.clear()
        self._high_queue.clear()
        self._stats = {k: 0 for k in self._stats}
    
    def set_callbacks(
        self,
        on_request: Optional[Callable] = None,
        on_response: Optional[Callable] = None,
        on_pair_complete: Optional[Callable] = None
    ):
        """Set async callbacks"""
        self._on_request_callback = on_request
        self._on_response_callback = on_response
        self._on_pair_complete = on_pair_complete


if __name__ == "__main__":
    print("ApexScanner Core Interceptor Module loaded")
    print("RequestType:", [e.value for e in RequestType])
    print("SensitivityLevel:", [e.value for e in SensitivityLevel])
