"""
Playwright-based Dynamic Browser Engine
Headless browser with JS rendering, XHR/Fetch interception, and DOM analysis
For modern SPA applications (Angular, React, Vue)
"""
import asyncio
import json
import time
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, urljoin
import logging

try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Response, Request
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class NetworkRequest:
    """Captured network request"""
    url: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    post_data: Optional[str] = None
    resource_type: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class NetworkResponse:
    """Captured network response"""
    url: str
    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    body_json: Optional[Dict] = None
    response_time: float = 0.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class DiscoveredEndpoint:
    """Discovered API endpoint from network traffic"""
    url: str
    method: str
    parameters: List[str] = field(default_factory=list)
    auth_required: bool = False
    content_type: str = ""
    response_sample: Optional[str] = None
    source: str = ""  # xhr, fetch, websocket, etc.


@dataclass
class BrowserSession:
    """Browser session state"""
    session_id: str
    url: str
    cookies: List[Dict] = field(default_factory=list)
    local_storage: Dict[str, str] = field(default_factory=dict)
    session_storage: Dict[str, str] = field(default_factory=dict)
    jwt_tokens: List[str] = field(default_factory=list)
    dom_snapshot: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


class PlaywrightEngine:
    """
    Async headless browser engine for DAST scanning
    Supports JS rendering, network interception, and dynamic analysis
    """

    def __init__(
        self,
        headless: bool = True,
        timeout: int = 30000,
        wait_for_network_idle: bool = True,
        user_agent: Optional[str] = None,
        viewport: Dict[str, int] = None,
        proxy: Optional[Dict] = None,
        ignore_https_errors: bool = True
    ):
        self.headless = headless
        self.timeout = timeout
        self.wait_for_network_idle = wait_for_network_idle
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        self.viewport = viewport or {"width": 1920, "height": 1080}
        self.proxy = proxy
        self.ignore_https_errors = ignore_https_errors

        self._playwright = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None

        self._requests: List[NetworkRequest] = []
        self._responses: List[NetworkResponse] = []
        self._endpoints: Set[str] = set()
        self._discovered_endpoints: List[DiscoveredEndpoint] = []
        self._console_messages: List[Dict] = []
        self._errors: List[Dict] = []

        self._request_callback: Optional[Callable] = None
        self._response_callback: Optional[Callable] = None

        self._base_url: Optional[str] = None
        self._scan_depth: int = 0
        self._max_depth: int = 5

        logger.info("PlaywrightEngine initialized")

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def start(self):
        """Start browser instance"""
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError("Playwright not installed. Run: pip install playwright && playwright install")

        self._playwright = await async_playwright().start()

        browser_args = [
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-web-security",
            "--disable-features=IsolateOrigins,site-per-process",
        ]

        self._browser = await self._playwright.chromium.launch(
            headless=self.headless,
            args=browser_args,
            ignore_default_args=["--enable-automation"]
        )

        context_options = {
            "user_agent": self.user_agent,
            "viewport": self.viewport,
            "ignore_https_errors": self.ignore_https_errors,
            "java_script_enabled": True,
            "bypass_csp": True,
            "extra_http_headers": {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
            }
        }

        if self.proxy:
            context_options["proxy"] = self.proxy

        self._context = await self._browser.new_context(**context_options)
        self._page = await self._context.new_page()

        # Disable webdriver detection
        await self._page.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined,
            });
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5],
            });
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'],
            });
        """)

        # Setup request/response interception
        await self._setup_interception()

        logger.info("Browser started successfully")

    async def _setup_interception(self):
        """Setup network request/response interception"""
        
        # Setup request interception using route
        await self._page.route("**/*", self._handle_request)
        
        # Setup response capture
        self._page.on("response", self._handle_response)
        
        # Setup console message capture
        self._page.on("console", self._handle_console)
        
        # Setup error capture
        self._page.on("pageerror", self._handle_pageerror)
    
    async def _handle_request(self, route, request: Request):
        """Handle intercepted request"""
        req_data = NetworkRequest(
            url=request.url,
            method=request.method,
            headers={k: str(v) for k, v in request.headers.items()},
            post_data=request.post_data,
            resource_type=request.resource_type
        )
        self._requests.append(req_data)

        # Extract endpoint info
        self._extract_endpoint_info(request)

        if self._request_callback:
            await self._request_callback(req_data)

        logger.debug(f"Request: {request.method} {request.url}")
        
        # Continue the request
        await route.continue_()
    
    async def _handle_response(self, response: Response):
        """Handle response"""
        start_time = time.time()

        try:
            body = await response.text()
            response_time = (time.time() - start_time) * 1000

            # Try to parse JSON
            body_json = None
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                try:
                    body_json = json.loads(body)
                except (json.JSONDecodeError, TypeError):
                    pass

            resp_data = NetworkResponse(
                url=response.url,
                status=response.status,
                headers={k: str(v) for k, v in response.headers.items()},
                body=body[:10000] if body else None,  # Limit body size
                body_json=body_json,
                response_time=response_time
            )
            self._responses.append(resp_data)

            if self._response_callback:
                await self._response_callback(resp_data)

            logger.debug(f"Response: {response.status} {response.url}")

        except Exception as e:
            logger.error(f"Error capturing response: {e}")
    
    async def _handle_console(self, msg):
        """Handle console messages"""
        self._console_messages.append({
            "type": msg.type,
            "text": msg.text,
            "location": f"{msg.location.get('url', '')}:{msg.location.get('lineNumber', '')}"
        })
    
    async def _handle_pageerror(self, error):
        """Handle page errors"""
        self._errors.append({
            "message": str(error),
            "timestamp": time.time()
        })

    def _extract_endpoint_info(self, request: Request):
        """Extract API endpoint information from request"""
        url = request.url
        method = request.method

        # Skip static resources
        skip_extensions = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2'}
        if any(url.lower().endswith(ext) for ext in skip_extensions):
            return

        # Check if it's an API endpoint
        api_indicators = ['/api/', '/rest/', '/v1/', '/v2/', '/graphql', '?', '=']
        if not any(ind in url for ind in api_indicators):
            return

        if url not in self._endpoints:
            self._endpoints.add(url)

            # Extract parameters from URL
            parsed = urlparse(url)
            params = list(parsed.query.split('&')) if parsed.query else []

            # Check auth
            headers = request.headers
            auth_required = bool(
                headers.get('authorization') or
                headers.get('cookie') or
                'token' in url.lower()
            )

            endpoint = DiscoveredEndpoint(
                url=url,
                method=method,
                parameters=params,
                auth_required=auth_required,
                content_type=headers.get('content-type', ''),
                source=request.resource_type
            )
            self._discovered_endpoints.append(endpoint)
            logger.info(f"Discovered endpoint: {method} {url}")

    async def navigate(self, url: str, wait_until: str = "networkidle", timeout: int = None) -> Page:
        """Navigate to URL and wait for rendering"""
        if not self._page:
            await self.start()

        self._base_url = url
        self._requests.clear()
        self._responses.clear()
        self._endpoints.clear()
        self._discovered_endpoints.clear()
        self._console_messages.clear()
        self._errors.clear()

        logger.info(f"Navigating to: {url}")

        try:
            await self._page.goto(
                url,
                wait_until=wait_until,
                timeout=timeout or self.timeout
            )

            # Wait for network idle
            if self.wait_for_network_idle:
                await self._page.wait_for_load_state("networkidle", timeout=self.timeout)

            # Additional wait for dynamic content
            await self._wait_for_dynamic_content()

            logger.info(f"Page loaded: {url}")
            return self._page

        except Exception as e:
            logger.error(f"Navigation error: {e}")
            raise

    async def _wait_for_dynamic_content(self, timeout: int = 5000):
        """Wait for dynamic content to render"""
        try:
            # Wait for common SPA indicators
            await asyncio.wait_for(
                self._page.wait_for_function("document.readyState === 'complete'"),
                timeout=timeout / 1000
            )

            # Wait for Angular
            try:
                await self._page.wait_for_function(
                    "() => window.angular || document.querySelector('[ng-app]')",
                    timeout=2000
                )
            except:
                pass

            # Wait for React
            try:
                await self._page.wait_for_function(
                    "() => window.React || document.querySelector('[data-reactroot]')",
                    timeout=2000
                )
            except:
                pass

            # Wait for Vue
            try:
                await self._page.wait_for_function(
                    "() => window.Vue || document.querySelector('[data-v-')",
                    timeout=2000
                )
            except:
                pass

        except asyncio.TimeoutError:
            logger.debug("Dynamic content wait timeout")

    async def click(self, selector: str, timeout: int = 5000) -> bool:
        """Click element and wait for network activity"""
        try:
            await self._page.click(selector, timeout=timeout)
            await self._page.wait_for_load_state("networkidle", timeout=5000)
            return True
        except Exception as e:
            logger.error(f"Click error: {e}")
            return False

    async def fill(self, selector: str, value: str) -> bool:
        """Fill input field"""
        try:
            await self._page.fill(selector, value)
            return True
        except Exception as e:
            logger.error(f"Fill error: {e}")
            return False

    async def execute_script(self, script: str) -> Any:
        """Execute JavaScript in browser context"""
        try:
            return await self._page.evaluate(script)
        except Exception as e:
            logger.error(f"Script execution error: {e}")
            return None

    async def get_dom_snapshot(self) -> Optional[str]:
        """Get current DOM snapshot"""
        try:
            return await self._page.content()
        except Exception as e:
            logger.error(f"DOM snapshot error: {e}")
            return None

    async def get_element_text(self, selector: str) -> Optional[str]:
        """Get text content of element"""
        try:
            element = await self._page.query_selector(selector)
            if element:
                return await element.text_content()
            return None
        except Exception as e:
            logger.error(f"Get element text error: {e}")
            return None

    async def check_element_exists(self, selector: str) -> bool:
        """Check if element exists in DOM"""
        try:
            element = await self._page.query_selector(selector)
            return element is not None
        except Exception as e:
            logger.error(f"Element exists error: {e}")
            return False

    async def get_window_object(self, key: str) -> Any:
        """Get value from window object"""
        try:
            return await self._page.evaluate(f"window.{key}")
        except Exception as e:
            logger.error(f"Get window object error: {e}")
            return None

    async def set_window_object(self, key: str, value: Any):
        """Set value in window object"""
        try:
            await self._page.evaluate(f"window.{key} = {json.dumps(value)}")
        except Exception as e:
            logger.error(f"Set window object error: {e}")

    async def get_cookies(self) -> List[Dict]:
        """Get browser cookies"""
        try:
            return await self._context.cookies()
        except Exception as e:
            logger.error(f"Get cookies error: {e}")
            return []

    async def set_cookies(self, cookies: List[Dict]):
        """Set browser cookies"""
        try:
            await self._context.add_cookies(cookies)
        except Exception as e:
            logger.error(f"Set cookies error: {e}")

    async def get_local_storage(self, origin: str = None) -> Dict[str, str]:
        """Get local storage"""
        try:
            if origin:
                return await self._page.evaluate(f"localStorage")
            return await self._page.evaluate("() => ({...localStorage})")
        except Exception as e:
            logger.error(f"Get local storage error: {e}")
            return {}

    async def extract_jwt_tokens(self) -> List[str]:
        """Extract JWT tokens from storage"""
        tokens = []

        # Check cookies
        cookies = await self.get_cookies()
        for cookie in cookies:
            name = cookie.get('name', '').lower()
            if 'token' in name or 'jwt' in name or 'auth' in name or 'session' in name:
                value = cookie.get('value', '')
                if value.startswith('eyJ'):
                    tokens.append(value)

        # Check local storage
        try:
            local_storage = await self.get_local_storage()
            for key, value in local_storage.items():
                key_lower = key.lower()
                if ('token' in key_lower or 'jwt' in key_lower or 'auth' in key_lower):
                    if isinstance(value, str) and value.startswith('eyJ'):
                        tokens.append(value)
                    elif isinstance(value, str):
                        # Try to extract JWT from JSON
                        try:
                            data = json.loads(value)
                            if isinstance(data, dict):
                                for v in data.values():
                                    if isinstance(v, str) and v.startswith('eyJ'):
                                        tokens.append(v)
                        except:
                            pass
        except Exception as e:
            logger.error(f"Extract JWT error: {e}")

        return list(set(tokens))

    async def crawl(self, max_depth: int = 3, max_pages: int = 50) -> List[DiscoveredEndpoint]:
        """
        Crawl the application discovering endpoints
        Clicks links, submits forms, captures network traffic
        """
        self._max_depth = max_depth
        visited_urls: Set[str] = set()
        pages_visited = 0

        async def crawl_recursive(url: str, depth: int):
            nonlocal pages_visited

            if depth > self._max_depth or pages_visited >= max_pages:
                return

            if url in visited_urls:
                return

            try:
                await self.navigate(url)
                visited_urls.add(url)
                pages_visited += 1

                logger.info(f"Crawling: {url} (depth: {depth})")

                # Get all clickable links
                links = await self._page.query_selector_all('a[href]')
                for link in links[:20]:  # Limit links per page
                    try:
                        href = await link.get_attribute('href')
                        if href and href.startswith(self._base_url or ''):
                            if href not in visited_urls:
                                await crawl_recursive(href, depth + 1)
                    except:
                        continue

                # Click buttons to trigger more endpoints
                buttons = await self._page.query_selector_all('button, [role="button"]')
                for button in buttons[:10]:
                    try:
                        await button.click(timeout=3000)
                        await asyncio.sleep(1)  # Wait for navigation
                    except:
                        continue

            except Exception as e:
                logger.error(f"Crawl error: {e}")

        await crawl_recursive(self._base_url or "", 0)
        return self._discovered_endpoints

    def get_discovered_endpoints(self) -> List[DiscoveredEndpoint]:
        """Get all discovered endpoints"""
        return self._discovered_endpoints

    def get_requests(self) -> List[NetworkRequest]:
        """Get all captured requests"""
        return self._requests

    def get_responses(self) -> List[NetworkResponse]:
        """Get all captured responses"""
        return self._responses

    def get_console_messages(self) -> List[Dict]:
        """Get console messages"""
        return self._console_messages

    def get_errors(self) -> List[Dict]:
        """Get page errors"""
        return self._errors

    async def save_session(self, session_id: str) -> BrowserSession:
        """Save current browser session"""
        cookies = await self.get_cookies()
        local_storage = await self.get_local_storage()
        jwt_tokens = await self.extract_jwt_tokens()
        dom_snapshot = await self.get_dom_snapshot()

        session = BrowserSession(
            session_id=session_id,
            url=self._page.url if self._page else "",
            cookies=cookies,
            local_storage=local_storage,
            jwt_tokens=jwt_tokens,
            dom_snapshot=dom_snapshot
        )
        return session

    async def restore_session(self, session: BrowserSession):
        """Restore browser session"""
        if session.cookies:
            await self.set_cookies(session.cookies)

        # Restore local storage
        if session.local_storage and self._page:
            for key, value in session.local_storage.items():
                try:
                    await self._page.evaluate(f"localStorage.setItem('{key}', '{value}')")
                except:
                    pass

        logger.info(f"Session restored: {session.session_id}")

    async def close(self):
        """Close browser"""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        logger.info("Browser closed")


# Utility functions
async def create_browser_session(
    target_url: str,
    headless: bool = True,
    crawl: bool = True
) -> tuple[PlaywrightEngine, List[DiscoveredEndpoint]]:
    """
    Create browser session and optionally crawl the site
    Returns engine and discovered endpoints
    """
    engine = PlaywrightEngine(headless=headless)
    await engine.start()

    await engine.navigate(target_url)

    endpoints = []
    if crawl:
        endpoints = await engine.crawl()

    return engine, endpoints


if __name__ == "__main__":
    # Test
    async def test():
        engine = PlaywrightEngine(headless=True)
        await engine.start()

        await engine.navigate("http://localhost:3000")

        # Execute test script
        result = await engine.execute_script("document.title")
        print(f"Page title: {result}")

        # Get JWT tokens
        tokens = await engine.extract_jwt_tokens()
        print(f"JWT tokens: {tokens}")

        # Crawl
        endpoints = await engine.crawl(max_depth=2)
        print(f"Discovered {len(endpoints)} endpoints")

        await engine.close()

    if PLAYWRIGHT_AVAILABLE:
        asyncio.run(test())
    else:
        print("Playwright not available")
