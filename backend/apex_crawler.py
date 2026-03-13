"""
ApexScanner - Auto-Crawler Module
Intelligent crawler that clicks buttons, fills forms, and triggers hidden APIs
"""
import asyncio
import time
import re
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
from enum import Enum
import logging

try:
    from playwright.async_api import Page, ElementHandle
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class InteractionType(Enum):
    """Types of page interactions"""
    CLICK = "click"
    FILL = "fill"
    SELECT = "select"
    CHECK = "check"
    SUBMIT = "submit"
    HOVER = "hover"
    FOCUS = "focus"


@dataclass
class InteractionResult:
    """Result of page interaction"""
    element: str
    interaction_type: InteractionType
    success: bool
    triggered_network_activity: bool
    new_endpoints: List[str] = field(default_factory=list)
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class CrawlerState:
    """Crawler state"""
    current_url: str
    depth: int
    visited_urls: Set[str] = field(default_factory=set)
    interacted_elements: List[str] = field(default_factory=list)
    discovered_endpoints: List[str] = field(default_factory=list)
    network_requests: List[Dict] = field(default_factory=list)


class AutoCrawler:
    """
    Intelligent auto-crawler for SPA applications
    Automatically clicks buttons, fills forms, and discovers hidden endpoints
    """
    
    # Selectors for interactive elements
    CLICKABLE_SELECTORS = [
        'button',
        'a[href]',
        'input[type="button"]',
        'input[type="submit"]',
        'input[type="reset"]',
        '[role="button"]',
        '[onclick]',
        '[ng-click]',
        '[v-on:click]',
        '.btn',
        '.button',
        '[tabindex]',
    ]
    
    # Form selectors
    FORM_SELECTORS = [
        'form',
        'input[type="text"]',
        'input[type="email"]',
        'input[type="password"]',
        'input[type="number"]',
        'input[type="search"]',
        'input[type="tel"]',
        'input[type="url"]',
        'textarea',
        'select',
    ]
    
    # Navigation blockers (don't click these)
    NAVIGATION_BLOCKERS = [
        'a[target="_blank"]',
        'a[href^="javascript:"]',
        'a[href^="#"]',
        'a[href^="mailto:"]',
        'a[href^="tel:"]',
    ]
    
    # Network activity indicators
    NETWORK_INDICATORS = [
        'loading',
        'spinner',
        'loader',
        'fetching',
        'saving',
    ]
    
    def __init__(
        self,
        page: 'Page',
        base_url: str,
        max_depth: int = 5,
        max_pages: int = 50,
        timeout: int = 30000,
        wait_for_network: bool = True
    ):
        self.page = page
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.wait_for_network = wait_for_network
        
        # State
        self._state = CrawlerState(
            current_url=base_url,
            depth=0
        )
        
        # Statistics
        self._stats = {
            'pages_visited': 0,
            'elements_clicked': 0,
            'forms_filled': 0,
            'endpoints_discovered': 0,
            'network_requests_captured': 0,
            'errors': 0
        }
        
        # Network request storage
        self._network_requests: List[Dict] = []
        self._discovered_endpoints: Set[str] = set()
        
        # Network request storage
        self._network_requests: List[Dict] = []
        self._discovered_endpoints: Set[str] = set()

    async def _setup_network_monitoring(self):
        """Setup network request monitoring"""
        if not self.page:
            return
            
        @self.page.on("request")
        def on_request(request):
            self._network_requests.append({
                'url': request.url,
                'method': request.method,
                'resource_type': request.resource_type,
                'headers': dict(request.headers),
                'post_data': request.post_data,
                'timestamp': time.time()
            })
            self._stats['network_requests_captured'] += 1
            
            # Extract endpoint
            if self._is_api_endpoint(request.url):
                self._discovered_endpoints.add(request.url)
                self._stats['endpoints_discovered'] += 1
    
    async def crawl(self) -> Dict[str, Any]:
        """
        Main crawling method
        Navigates through the application discovering endpoints
        """
        logger.info(f"Starting auto-crawl from {self.base_url}")
        logger.info(f"Max depth: {self.max_depth}, Max pages: {self.max_pages}")
        
        # Setup network monitoring
        await self._setup_network_monitoring()
        
        # Navigate to base URL
        await self._navigate_to_page(self.base_url)
        
        # Start recursive crawling
        await self._crawl_recursive(self.base_url, 0)
        
        logger.info(f"Crawling complete: {self._stats['pages_visited']} pages, {self._stats['endpoints_discovered']} endpoints")
        
        return self._get_crawl_results()
    
    async def _crawl_recursive(self, url: str, depth: int):
        """Recursively crawl pages"""
        # Check limits
        if depth > self.max_depth:
            logger.debug(f"Max depth reached at {url}")
            return
        
        if self._stats['pages_visited'] >= self.max_pages:
            logger.info(f"Max pages limit reached")
            return
        
        # Check if already visited
        if url in self._state.visited_urls:
            return
        
        self._state.visited_urls.add(url)
        self._state.current_url = url
        self._state.depth = depth
        
        logger.info(f"Crawling: {url} (depth: {depth})")
        self._stats['pages_visited'] += 1
        
        # Wait for page to load
        await self._wait_for_page_ready()
        
        # Interact with elements
        await self._interact_with_page()
        
        # Find and follow links
        await self._follow_links(depth)
    
    async def _interact_with_page(self):
        """Interact with interactive elements on the page"""
        # Click buttons
        await self._click_buttons()
        
        # Fill forms
        await self._fill_forms()
        
        # Trigger hover states
        await self._trigger_hovers()
    
    async def _click_buttons(self):
        """Click all clickable elements"""
        for selector in self.CLICKABLE_SELECTORS:
            try:
                elements = await self.page.query_selector_all(selector)
                
                for i, element in enumerate(elements[:10]):  # Limit per selector
                    try:
                        # Check if element is visible
                        is_visible = await self._is_element_visible(element)
                        if not is_visible:
                            continue
                        
                        # Get element description
                        element_desc = await self._get_element_description(element)
                        
                        # Skip if already interacted
                        if element_desc in self._state.interacted_elements:
                            continue
                        
                        # Click element
                        network_before = len(self._network_requests)
                        
                        await element.click(timeout=3000)
                        
                        # Wait for network activity
                        if self.wait_for_network:
                            await self._wait_for_network_idle(timeout=5000)
                        
                        network_after = len(self._network_requests)
                        
                        # Record interaction
                        result = InteractionResult(
                            element=element_desc,
                            interaction_type=InteractionType.CLICK,
                            success=True,
                            triggered_network_activity=network_after > network_before,
                            new_endpoints=list(self._discovered_endpoints)[-5:]
                        )
                        
                        self._state.interacted_elements.append(element_desc)
                        self._stats['elements_clicked'] += 1
                        
                        logger.debug(f"Clicked: {element_desc}")
                        
                        # Check if new page loaded
                        if self.page.url != self._state.current_url:
                            await self._crawl_recursive(self.page.url, self._state.depth + 1)
                        
                    except Exception as e:
                        logger.debug(f"Click error: {e}")
                        self._stats['errors'] += 1
                        
            except Exception as e:
                logger.debug(f"Button click error: {e}")
    
    async def _fill_forms(self):
        """Fill and submit forms"""
        try:
            forms = await self.page.query_selector_all('form')
            
            for form in forms[:5]:  # Limit forms
                try:
                    # Find input fields
                    inputs = await form.query_selector_all('input, textarea, select')
                    
                    # Fill each input
                    for input_el in inputs[:10]:
                        try:
                            tag_name = await input_el.evaluate('el => el.tagName.toLowerCase()')
                            input_type = await input_el.get_attribute('type') or 'text'
                            
                            if tag_name == 'input':
                                if input_type in ['text', 'email', 'password', 'search', 'tel', 'url']:
                                    # Generate realistic test data
                                    test_value = self._generate_test_data(input_type)
                                    await input_el.fill(test_value, timeout=2000)
                                    
                            elif tag_name == 'textarea':
                                await input_el.fill('Test content', timeout=2000)
                            
                            elif tag_name == 'select':
                                # Select first option
                                await input_el.select_option(index=1, timeout=2000)
                            
                            self._stats['forms_filled'] += 1
                            
                        except Exception as e:
                            logger.debug(f"Fill input error: {e}")
                    
                    # Submit form
                    submit_button = await form.query_selector('input[type="submit"], button[type="submit"]')
                    if submit_button:
                        await submit_button.click(timeout=3000)
                        await self._wait_for_network_idle(timeout=5000)
                    
                except Exception as e:
                    logger.debug(f"Form fill error: {e}")
                    self._stats['errors'] += 1
                    
        except Exception as e:
            logger.debug(f"Form interaction error: {e}")
    
    async def _trigger_hovers(self):
        """Trigger hover states to reveal hidden menus"""
        try:
            hoverable = await self.page.query_selector_all(
                'details, summary, [data-toggle="dropdown"], .dropdown-toggle, [aria-haspopup="true"]'
            )
            
            for element in hoverable[:10]:
                try:
                    await element.hover(timeout=2000)
                    await asyncio.sleep(0.5)  # Wait for animation
                    
                except Exception as e:
                    logger.debug(f"Hover error: {e}")
                    
        except Exception as e:
            logger.debug(f"Hover trigger error: {e}")
    
    async def _follow_links(self, depth: int):
        """Follow internal links"""
        try:
            links = await self.page.query_selector_all('a[href]')
            
            for link in links[:20]:  # Limit links per page
                try:
                    href = await link.get_attribute('href')
                    
                    if not href:
                        continue
                    
                    # Skip external, javascript, mailto, etc.
                    if self._should_skip_link(href):
                        continue
                    
                    # Convert to absolute URL
                    full_url = urljoin(self.base_url, href)
                    
                    # Skip if already visited
                    if full_url in self._state.visited_urls:
                        continue
                    
                    # Navigate to link
                    await self._navigate_to_page(full_url)
                    await self._crawl_recursive(full_url, depth + 1)
                    
                except Exception as e:
                    logger.debug(f"Link follow error: {e}")
                    
        except Exception as e:
            logger.debug(f"Follow links error: {e}")
    
    async def _navigate_to_page(self, url: str):
        """Navigate to URL"""
        try:
            await self.page.goto(url, wait_until='networkidle', timeout=self.timeout)
        except Exception as e:
            logger.debug(f"Navigation error: {e}")
            self._stats['errors'] += 1
    
    async def _wait_for_page_ready(self, timeout: int = 10000):
        """Wait for page to be fully loaded and interactive"""
        try:
            # Wait for network idle
            if self.wait_for_network:
                await self.page.wait_for_load_state('networkidle', timeout=timeout)
            
            # Wait for common SPA frameworks
            await self._wait_for_frameworks()
            
            # Additional wait for dynamic content
            await asyncio.sleep(1)
            
        except Exception as e:
            logger.debug(f"Page ready wait error: {e}")
    
    async def _wait_for_frameworks(self, timeout: int = 3000):
        """Wait for SPA frameworks to initialize"""
        try:
            # Angular
            await self.page.wait_for_function(
                "() => window.angular || document.querySelector('[ng-app]')",
                timeout=timeout
            )
        except:
            pass
        
        try:
            # React
            await self.page.wait_for_function(
                "() => window.React || document.querySelector('[data-reactroot]')",
                timeout=timeout
            )
        except:
            pass
        
        try:
            # Vue
            await self.page.wait_for_function(
                "() => window.Vue || document.querySelector('[data-v-]')",
                timeout=timeout
            )
        except:
            pass
    
    async def _wait_for_network_idle(self, timeout: int = 5000):
        """Wait for network activity to settle"""
        try:
            await self.page.wait_for_load_state('networkidle', timeout=timeout)
        except:
            pass
    
    def _is_api_endpoint(self, url: str) -> bool:
        """Check if URL is an API endpoint"""
        # Skip static resources
        static_extensions = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2']
        if any(url.lower().endswith(ext) for ext in static_extensions):
            return False
        
        # Check for API indicators
        api_indicators = ['/api/', '/rest/', '/v1/', '/v2/', '/graphql', '/auth/', '/user/', '/admin/']
        return any(indicator in url for indicator in api_indicators)
    
    def _should_skip_link(self, href: str) -> bool:
        """Check if link should be skipped"""
        # Skip external links
        if href.startswith(('http://', 'https://')):
            if self.base_domain not in href:
                return True
        
        # Skip special protocols
        if href.startswith(('javascript:', 'mailto:', 'tel:', '#', 'data:')):
            return True
        
        # Skip file downloads
        file_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar', '.gz']
        if any(href.lower().endswith(ext) for ext in file_extensions):
            return True
        
        return False
    
    def _is_element_visible(self, element: 'ElementHandle') -> bool:
        """Check if element is visible and interactable"""
        try:
            return element.is_visible() and element.is_enabled()
        except:
            return False
    
    async def _get_element_description(self, element: 'ElementHandle') -> str:
        """Get human-readable description of element"""
        try:
            tag_name = await element.evaluate('el => el.tagName.toLowerCase()')
            text = await element.inner_text()
            text = text.strip()[:50] if text else ''
            
            # Get additional attributes
            id_attr = await element.get_attribute('id') or ''
            class_attr = await element.get_attribute('class') or ''
            name_attr = await element.get_attribute('name') or ''
            
            description = f"{tag_name}"
            if text:
                description += f":{text}"
            if id_attr:
                description += f"#{id_attr}"
            if name_attr:
                description += f"[name={name_attr}]"
            
            return description
            
        except Exception as e:
            return f"element_{id(element)}"
    
    def _generate_test_data(self, input_type: str) -> str:
        """Generate realistic test data for input type"""
        test_data = {
            'text': 'test_value',
            'email': 'test@example.com',
            'password': 'Test123!@#',
            'number': '123',
            'search': 'search query',
            'tel': '+1234567890',
            'url': 'https://example.com',
        }
        return test_data.get(input_type, 'test_value')
    
    def _get_crawl_results(self) -> Dict[str, Any]:
        """Get crawling results"""
        return {
            'statistics': self._stats,
            'visited_urls': list(self._state.visited_urls),
            'discovered_endpoints': list(self._discovered_endpoints),
            'network_requests': self._network_requests[-100:],  # Last 100 requests
            'interacted_elements': self._state.interacted_elements
        }
    
    def get_discovered_endpoints(self) -> List[str]:
        """Get all discovered endpoints"""
        return list(self._discovered_endpoints)
    
    def get_network_requests(self) -> List[Dict]:
        """Get all captured network requests"""
        return self._network_requests
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get crawler statistics"""
        return self._stats


if __name__ == "__main__":
    print("ApexScanner Auto-Crawler Module loaded")
