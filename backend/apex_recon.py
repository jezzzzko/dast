"""
ApexScanner - Deep Reconnaissance Module
JS Bundle parsing, hidden endpoint discovery, API mapping
"""
import asyncio
import re
import json
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
import logging
import hashlib

try:
    from playwright.async_api import Page
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class DiscoveredEndpoint:
    """Discovered API endpoint"""
    url: str
    method: str = "GET"
    source: str = ""  # js_file, html, network, dom
    parameters: List[str] = field(default_factory=list)
    auth_required: bool = False
    description: str = ""
    confidence: float = 0.0
    raw_match: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'url': self.url,
            'method': self.method,
            'source': self.source,
            'parameters': self.parameters,
            'auth_required': self.auth_required,
            'description': self.description,
            'confidence': self.confidence
        }


@dataclass
class JSBundle:
    """Parsed JavaScript bundle"""
    url: str
    content: str
    size: int
    hash: str
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    secrets: List[Dict] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)


class DeepReconScanner:
    """
    Deep reconnaissance scanner for SPA applications
    Discovers hidden endpoints, API routes, and sensitive data in JS bundles
    """
    
    # Regex patterns for endpoint discovery
    ENDPOINT_PATTERNS = [
        # API routes
        (r'["\'](/api/[^\s"\']+)["\']', 'api_route'),
        (r'["\'](/rest/[^\s"\']+)["\']', 'rest_route'),
        (r'["\'](/v[0-9]+/[^\s"\']+)["\']', 'versioned_api'),
        (r'["\'](/graphql)[^\s"\']*["\']', 'graphql'),
        
        # HTTP methods
        (r'(?:GET|POST|PUT|DELETE|PATCH)\s*[:=]\s*["\']([^\s"\']+)["\']', 'method_route'),
        (r'(?:get|post|put|delete|patch)\s*\(\s*["\']([^\s"\']+)["\']', 'method_call'),
        
        # Fetch/XHR calls
        (r'fetch\s*\(\s*["\']([^\s"\']+)["\']', 'fetch_call'),
        (r'axios\.(?:get|post|put|delete)\s*\(\s*["\']([^\s"\']+)["\']', 'axios_call'),
        (r'\$http\s*\(\s*{\s*url:\s*["\']([^\s"\']+)["\']', 'http_call'),
        
        # Route definitions (Angular, React, Vue)
        (r'(?:path|route)\s*[:=]\s*["\']([^\s"\']+)["\']', 'route_def'),
        (r'Router\.route\s*\(\s*["\']([^\s"\']+)["\']', 'router_route'),
        
        # URL construction
        (r'["\'](/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*)["\']', 'url_path'),
    ]
    
    # Patterns for sensitive data
    SECRET_PATTERNS = [
        (r'["\']api[_-]?key["\']\s*[:=]\s*["\']([^\s"\']+)["\']', 'API Key'),
        (r'["\']secret["\']\s*[:=]\s*["\']([^\s"\']+)["\']', 'Secret'),
        (r'["\']token["\']\s*[:=]\s*["\']([^\s"\']+)["\']', 'Token'),
        (r'["\']password["\']\s*[:=]\s*["\']([^\s"\']+)["\']', 'Password'),
        (r'["\']aws[_-]?access["\']\s*[:=]\s*["\']([^\s"\']+)["\']', 'AWS Access'),
        (r'["\']aws[_-]?secret["\']\s*[:=]\s*["\']([^\s"\']+)["\']', 'AWS Secret'),
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
        (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Token'),
    ]
    
    # Patterns for comments
    COMMENT_PATTERNS = [
        r'//\s*(TODO|FIXME|HACK|XXX|NOTE)[:\s]*(.+?)(?:\n|$)',
        r'/\*\s*(TODO|FIXME|HACK|XXX|NOTE)[:\s]*(.+?)\*/',
        r'<!--\s*(TODO|FIXME|HACK|XXX|NOTE)[:\s]*(.+?)-->',
    ]
    
    def __init__(self, page: Optional['Page'] = None, base_url: str = ""):
        self.page = page
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc if base_url else ""
        
        # Storage
        self._js_bundles: List[JSBundle] = []
        self._endpoints: Dict[str, DiscoveredEndpoint] = {}
        self._secrets: List[Dict] = []
        self._comments: List[str] = []
        self._visited_urls: Set[str] = set()
        
        # Statistics
        self._stats = {
            'js_files_analyzed': 0,
            'endpoints_found': 0,
            'secrets_found': 0,
            'comments_found': 0
        }

    async def scan(self, max_depth: int = 3) -> Dict[str, Any]:
        """
        Perform deep reconnaissance scan
        """
        if not self.page:
            raise ValueError("Playwright page not provided")
        
        logger.info(f"Starting deep reconnaissance on {self.base_url}")
        
        # Step 1: Find all JS files
        js_files = await self._discover_js_files()
        logger.info(f"Found {len(js_files)} JavaScript files")
        
        # Step 2: Download and parse each JS file
        for js_url in js_files:
            if js_url not in self._visited_urls:
                await self._analyze_js_file(js_url)
        
        # Step 3: Extract endpoints from HTML
        await self._extract_endpoints_from_html()
        
        # Step 4: Extract endpoints from DOM
        await self._extract_endpoints_from_dom()
        
        # Step 5: Analyze network traffic (if interceptor attached)
        await self._analyze_network_traffic()
        
        # Build API map
        api_map = self._build_api_map()
        
        logger.info(f"Recon complete: {len(self._endpoints)} endpoints, {len(self._secrets)} secrets")
        
        return {
            'endpoints': [ep.to_dict() for ep in self._endpoints.values()],
            'secrets': self._secrets,
            'comments': self._comments,
            'api_map': api_map,
            'statistics': self._stats
        }
    
    async def _discover_js_files(self) -> List[str]:
        """Discover all JavaScript files loaded by the page"""
        js_files = []
        
        try:
            # Get script tags
            scripts = await self.page.query_selector_all('script[src]')
            for script in scripts:
                src = await script.get_attribute('src')
                if src and src.endswith('.js'):
                    full_url = urljoin(self.base_url, src)
                    if self.base_domain in urlparse(full_url).netloc:
                        js_files.append(full_url)
            
            # Get from performance API
            resources = await self.page.evaluate("""
                () => {
                    return performance.getEntriesByType('resource')
                        .filter(r => r.initiatorType === 'script' && r.name.endsWith('.js'))
                        .map(r => r.name);
                }
            """)
            
            for resource in resources:
                if resource not in js_files and self.base_domain in urlparse(resource).netloc:
                    js_files.append(resource)
            
        except Exception as e:
            logger.error(f"JS discovery error: {e}")
        
        return list(set(js_files))
    
    async def _analyze_js_file(self, url: str):
        """Download and analyze a JavaScript file"""
        try:
            self._visited_urls.add(url)
            
            # Download content
            response = await self.page.evaluate(f"""
                async () => {{
                    try {{
                        const response = await fetch('{url}');
                        return {{
                            status: response.status,
                            text: await response.text()
                        }};
                    }} catch (e) {{
                        return {{ status: 0, text: null }};
                    }}
                }}
            """)
            
            if response['status'] != 200 or not response['text']:
                return
            
            content = response['text']
            
            # Create bundle
            bundle = JSBundle(
                url=url,
                content=content,
                size=len(content),
                hash=hashlib.md5(content.encode()).hexdigest()
            )
            
            # Extract endpoints
            endpoints = self._extract_endpoints_from_content(content, url)
            bundle.endpoints = endpoints
            
            # Extract secrets
            secrets = self._extract_secrets_from_content(content, url)
            bundle.secrets = secrets
            
            # Extract comments
            comments = self._extract_comments_from_content(content, url)
            bundle.comments = comments
            
            # Store
            self._js_bundles.append(bundle)
            self._stats['js_files_analyzed'] += 1
            
            logger.debug(f"Analyzed JS: {url} ({len(endpoints)} endpoints, {len(secrets)} secrets)")
            
        except Exception as e:
            logger.error(f"JS analysis error: {e}")
    
    def _extract_endpoints_from_content(self, content: str, source: str) -> List[DiscoveredEndpoint]:
        """Extract endpoints from JS content"""
        endpoints = []
        
        for pattern, pattern_type in self.ENDPOINT_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                try:
                    # Extract URL
                    url = match.group(1) if match.lastindex >= 1 else match.group(0)
                    url = url.strip('"\'')
                    
                    # Skip if not a valid path
                    if not url.startswith('/') or url.startswith('//'):
                        continue
                    
                    # Determine method
                    method = self._infer_method(match.group(0), pattern_type)
                    
                    # Create endpoint
                    endpoint = DiscoveredEndpoint(
                        url=urljoin(self.base_url, url),
                        method=method,
                        source='js_file',
                        description=f"Found via {pattern_type} in {source}",
                        confidence=0.7,
                        raw_match=match.group(0)[:100]
                    )
                    
                    # Extract parameters
                    endpoint.parameters = self._extract_parameters(url)
                    
                    # Check auth requirement
                    endpoint.auth_required = self._check_auth_requirement(content, url)
                    
                    # Store
                    if endpoint.url not in self._endpoints:
                        endpoints.append(endpoint)
                        self._endpoints[endpoint.url] = endpoint
                        self._stats['endpoints_found'] += 1
                    
                except Exception as e:
                    logger.debug(f"Endpoint extraction error: {e}")
        
        return endpoints
    
    def _extract_secrets_from_content(self, content: str, source: str) -> List[Dict]:
        """Extract potential secrets from JS content"""
        secrets = []
        
        for pattern, secret_type in self.SECRET_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                try:
                    value = match.group(1) if match.lastindex >= 1 else match.group(0)
                    
                    # Skip common false positives
                    if value.lower() in ['undefined', 'null', 'none', 'placeholder', 'example']:
                        continue
                    
                    secrets.append({
                        'type': secret_type,
                        'value': value[:100] + '...' if len(value) > 100 else value,
                        'source': source,
                        'context': match.group(0)[:200],
                        'confidence': 'high' if secret_type.startswith('AWS') or secret_type.startswith('GitHub') else 'medium'
                    })
                    
                    self._stats['secrets_found'] += 1
                    
                except Exception as e:
                    logger.debug(f"Secret extraction error: {e}")
        
        return secrets
    
    def _extract_comments_from_content(self, content: str, source: str) -> List[str]:
        """Extract interesting comments from JS content"""
        comments = []
        
        for pattern in self.COMMENT_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                try:
                    comment_type = match.group(1)
                    comment_text = match.group(2).strip()
                    
                    comments.append(f"[{comment_type}] {comment_text} (in {source})")
                    self._stats['comments_found'] += 1
                    
                except Exception as e:
                    logger.debug(f"Comment extraction error: {e}")
        
        return comments
    
    async def _extract_endpoints_from_html(self):
        """Extract endpoints from HTML"""
        try:
            html = await self.page.content()
            
            # Look for endpoints in inline scripts
            script_pattern = r'<script[^>]*>(.*?)</script>'
            scripts = re.finditer(script_pattern, html, re.DOTALL | re.IGNORECASE)
            
            for script in scripts:
                content = script.group(1)
                if content and len(content) > 10:
                    endpoints = self._extract_endpoints_from_content(content, 'inline_script')
                    logger.debug(f"Found {len(endpoints)} endpoints in inline script")
            
        except Exception as e:
            logger.error(f"HTML endpoint extraction error: {e}")
    
    async def _extract_endpoints_from_dom(self):
        """Extract endpoints from DOM attributes"""
        try:
            # Look for data attributes, action attributes, etc.
            endpoints = await self.page.evaluate("""
                () => {
                    const endpoints = [];
                    
                    // Check action attributes
                    document.querySelectorAll('[action]').forEach(el => {
                        endpoints.push(el.getAttribute('action'));
                    });
                    
                    // Check data-api attributes
                    document.querySelectorAll('[data-api]').forEach(el => {
                        endpoints.push(el.getAttribute('data-api'));
                    });
                    
                    // Check form endpoints
                    document.querySelectorAll('form').forEach(el => {
                        if (el.action) endpoints.push(el.action);
                    });
                    
                    return endpoints.filter(e => e && e.startsWith('/'));
                }
            """)
            
            for url in endpoints:
                if url and url not in self._endpoints:
                    endpoint = DiscoveredEndpoint(
                        url=urljoin(self.base_url, url),
                        method='POST',
                        source='dom',
                        confidence=0.6
                    )
                    self._endpoints[endpoint.url] = endpoint
                    self._stats['endpoints_found'] += 1
            
        except Exception as e:
            logger.error(f"DOM endpoint extraction error: {e}")
    
    async def _analyze_network_traffic(self):
        """Analyze network traffic for endpoints"""
        # This would integrate with the interceptor
        # For now, extract from page's performance API
        try:
            resources = await self.page.evaluate("""
                () => {
                    return performance.getEntriesByType('resource')
                        .filter(r => r.initiatorType === 'xmlhttprequest' || r.initiatorType === 'fetch')
                        .map(r => ({
                            url: r.name,
                            duration: r.duration
                        }));
                }
            """)
            
            for resource in resources:
                url = resource.get('url', '')
                if url and url not in self._endpoints:
                    endpoint = DiscoveredEndpoint(
                        url=url,
                        method='GET',
                        source='network',
                        confidence=0.9
                    )
                    self._endpoints[endpoint.url] = endpoint
                    self._stats['endpoints_found'] += 1
            
        except Exception as e:
            logger.error(f"Network analysis error: {e}")
    
    def _build_api_map(self) -> Dict[str, Any]:
        """Build API map from discovered endpoints"""
        api_map = {
            'by_method': {},
            'by_source': {},
            'by_auth': {'required': [], 'not_required': []},
            'critical_endpoints': []
        }
        
        for endpoint in self._endpoints.values():
            # By method
            if endpoint.method not in api_map['by_method']:
                api_map['by_method'][endpoint.method] = []
            api_map['by_method'][endpoint.method].append(endpoint.url)
            
            # By source
            if endpoint.source not in api_map['by_source']:
                api_map['by_source'][endpoint.source] = []
            api_map['by_source'][endpoint.source].append(endpoint.url)
            
            # By auth
            if endpoint.auth_required:
                api_map['by_auth']['required'].append(endpoint.url)
            else:
                api_map['by_auth']['not_required'].append(endpoint.url)
            
            # Critical endpoints (auth endpoints without auth)
            if any(x in endpoint.url.lower() for x in ['auth', 'login', 'admin', 'user']) and not endpoint.auth_required:
                api_map['critical_endpoints'].append(endpoint.url)
        
        return api_map
    
    def _infer_method(self, context: str, pattern_type: str) -> str:
        """Infer HTTP method from context"""
        context_upper = context.upper()
        
        if 'POST' in context_upper or pattern_type in ['axios_call', 'fetch_call']:
            return 'POST'
        elif 'PUT' in context_upper:
            return 'PUT'
        elif 'DELETE' in context_upper:
            return 'DELETE'
        elif 'PATCH' in context_upper:
            return 'PATCH'
        
        return 'GET'
    
    def _extract_parameters(self, url: str) -> List[str]:
        """Extract parameters from URL"""
        params = []
        
        # Path parameters
        path_params = re.findall(r':([a-zA-Z_]+)', url)
        params.extend(path_params)
        
        # Query parameters
        if '?' in url:
            query_string = url.split('?')[1]
            query_params = re.findall(r'([a-zA-Z_]+)=', query_string)
            params.extend(query_params)
        
        return list(set(params))
    
    def _check_auth_requirement(self, content: str, url: str) -> bool:
        """Check if endpoint likely requires authentication"""
        # Look for auth headers near the endpoint
        context_window = 500
        
        # Find position in content
        pos = content.find(url)
        if pos == -1:
            return False
        
        # Get surrounding context
        start = max(0, pos - context_window)
        end = min(len(content), pos + context_window)
        context = content[start:end].lower()
        
        # Check for auth indicators
        auth_indicators = ['authorization', 'bearer', 'token', 'auth', 'jwt', 'cookie', 'session']
        
        return any(indicator in context for indicator in auth_indicators)
    
    def get_endpoints(self) -> List[DiscoveredEndpoint]:
        """Get all discovered endpoints"""
        return list(self._endpoints.values())
    
    def get_secrets(self) -> List[Dict]:
        """Get all discovered secrets"""
        return self._secrets
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get reconnaissance statistics"""
        return self._stats


if __name__ == "__main__":
    print("ApexScanner Deep Recon Module loaded")
