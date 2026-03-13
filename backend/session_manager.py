"""
Session Manager for DAST Scanner
Handles JWT/Cookie refresh, multi-user sessions (User A/B for BOLA testing),
and automatic session recovery during scans
"""
import asyncio
import time
import re
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import base64

import requests
from urllib.parse import urljoin

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SessionState(Enum):
    """Session state enumeration"""
    ACTIVE = "active"
    EXPIRED = "expired"
    INVALID = "invalid"
    REFRESHING = "refreshing"
    TERMINATED = "terminated"


@dataclass
class UserCredentials:
    """User credentials for authentication"""
    email: str
    password: str
    username: Optional[str] = None
    role: str = "user"  # user, admin, premium


@dataclass
class SessionData:
    """Session data container"""
    session_id: str
    user_id: str
    email: str
    role: str
    jwt_token: Optional[str] = None
    refresh_token: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    state: SessionState = SessionState.ACTIVE
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    last_used: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


class JWTDecoder:
    """Utility for decoding JWT tokens"""

    @staticmethod
    def decode_payload(token: str) -> Optional[Dict[str, Any]]:
        """Decode JWT payload without verification"""
        try:
            # Remove Bearer prefix if present
            if token.startswith("Bearer "):
                token = token[7:]

            parts = token.split(".")
            if len(parts) != 3:
                return None

            # Decode payload (second part)
            payload = parts[1]

            # Add padding if needed
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding

            decoded = base64.urlsafe_b64decode(payload)
            return json.loads(decoded)
        except Exception as e:
            logger.debug(f"JWT decode error: {e}")
            return None

    @staticmethod
    def is_expired(token: str, leeway: int = 0) -> bool:
        """Check if JWT token is expired"""
        payload = JWTDecoder.decode_payload(token)
        if not payload:
            return True

        exp = payload.get('exp')
        if not exp:
            return False  # No expiration = not expired

        return time.time() > (exp - leeway)

    @staticmethod
    def get_expiration(token: str) -> Optional[datetime]:
        """Get token expiration time"""
        payload = JWTDecoder.decode_payload(token)
        if not payload or 'exp' not in payload:
            return None

        return datetime.fromtimestamp(payload['exp'])

    @staticmethod
    def get_user_info(token: str) -> Dict[str, Any]:
        """Extract user info from JWT"""
        payload = JWTDecoder.decode_payload(token)
        if not payload:
            return {}

        return {
            'user_id': payload.get('id') or payload.get('userId') or payload.get('sub'),
            'email': payload.get('email'),
            'username': payload.get('username') or payload.get('name'),
            'role': payload.get('role') or payload.get('roles', ['user'])[0] if isinstance(payload.get('roles'), list) else payload.get('role'),
        }


class SessionManager:
    """
    Manages multiple user sessions for DAST scanning
    Supports automatic token refresh, session switching, and BOLA testing
    """

    def __init__(
        self,
        base_url: str,
        login_endpoint: str = "/rest/user/login",
        refresh_endpoint: Optional[str] = None,
        timeout: int = 30,
        auto_refresh: bool = True,
        token_leeway: int = 60  # Refresh token this many seconds before expiration
    ):
        self.base_url = base_url.rstrip('/')
        self.login_endpoint = login_endpoint
        self.refresh_endpoint = refresh_endpoint
        self.timeout = timeout
        self.auto_refresh = auto_refresh
        self.token_leeway = token_leeway

        self._sessions: Dict[str, SessionData] = {}
        self._active_session_id: Optional[str] = None
        self._session_counter = 0

        self._http_session = requests.Session()
        self._http_session.verify = False
        self._http_session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
        })

        logger.info(f"SessionManager initialized for {self.base_url}")

    def _generate_session_id(self, prefix: str = "session") -> str:
        """Generate unique session ID"""
        self._session_counter += 1
        return f"{prefix}_{self._session_counter}_{int(time.time())}"

    def create_session(
        self,
        credentials: UserCredentials,
        session_id: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> SessionData:
        """Create a new session with credentials"""
        sid = session_id or self._generate_session_id()

        session = SessionData(
            session_id=sid,
            user_id="",
            email=credentials.email,
            role=credentials.role,
            state=SessionState.ACTIVE,
            metadata=metadata or {}
        )

        self._sessions[sid] = session
        logger.info(f"Created session {sid} for user {credentials.email}")

        return session

    async def authenticate(self, session_id: str, credentials: Optional[UserCredentials] = None) -> bool:
        """
        Authenticate session and obtain JWT token
        """
        session = self._sessions.get(session_id)
        if not session:
            logger.error(f"Session {session_id} not found")
            return False

        if not credentials:
            # Try to use existing credentials
            logger.warning(f"No credentials provided for session {session_id}")
            return False

        login_url = urljoin(self.base_url, self.login_endpoint)

        try:
            response = self._http_session.post(
                login_url,
                json={
                    "email": credentials.email,
                    "password": credentials.password
                },
                timeout=self.timeout,
                allow_redirects=False
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    auth_data = data.get('authentication') or data

                    token = auth_data.get('token') or auth_data.get('jwt')

                    if token:
                        session.jwt_token = token
                        session.headers['Authorization'] = f'Bearer {token}'

                        # Extract user info from token
                        user_info = JWTDecoder.get_user_info(token)
                        session.user_id = user_info.get('user_id', '')
                        session.email = user_info.get('email', credentials.email)
                        session.role = user_info.get('role', credentials.role)

                        # Set expiration
                        exp_time = JWTDecoder.get_expiration(token)
                        if exp_time:
                            session.expires_at = exp_time.timestamp()

                        session.state = SessionState.ACTIVE
                        session.last_used = time.time()

                        # Store cookies
                        for cookie in self._http_session.cookies:
                            session.cookies[cookie.name] = cookie.value

                        logger.info(f"Session {session_id} authenticated as {session.email} ({session.role})")
                        return True

                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON response: {e}")
            else:
                logger.error(f"Authentication failed: HTTP {response.status_code}")

        except requests.RequestException as e:
            logger.error(f"Authentication error: {e}")

        session.state = SessionState.INVALID
        return False

    async def authenticate_user_a_and_b(
        self,
        credentials_a: UserCredentials,
        credentials_b: UserCredentials
    ) -> Tuple[Optional[SessionData], Optional[SessionData]]:
        """
        Authenticate two users for BOLA/IDOR testing
        Returns tuple of (session_a, session_b)
        """
        # Create and authenticate User A
        session_a = self.create_session(credentials_a, prefix="user_a")
        success_a = await self.authenticate(session_a.session_id, credentials_a)

        if not success_a:
            logger.error("Failed to authenticate User A")
            return None, None

        # Create and authenticate User B
        session_b = self.create_session(credentials_b, prefix="user_b")
        success_b = await self.authenticate(session_b.session_id, credentials_b)

        if not success_b:
            logger.error("Failed to authenticate User B")
            return session_a, None

        self._active_session_id = session_a.session_id
        logger.info(f"BOLA sessions created: User A ({session_a.role}) vs User B ({session_b.role})")

        return session_a, session_b

    def get_session(self, session_id: str) -> Optional[SessionData]:
        """Get session by ID"""
        return self._sessions.get(session_id)

    def get_active_session(self) -> Optional[SessionData]:
        """Get currently active session"""
        if self._active_session_id:
            return self._sessions.get(self._active_session_id)
        return None

    def switch_session(self, session_id: str) -> bool:
        """Switch to different session"""
        if session_id in self._sessions:
            self._active_session_id = session_id
            logger.info(f"Switched to session {session_id}")
            return True
        logger.error(f"Cannot switch to session {session_id}")
        return False

    def get_headers_for_session(self, session_id: Optional[str] = None) -> Dict[str, str]:
        """Get HTTP headers for session"""
        session = self.get_session(session_id) if session_id else self.get_active_session()

        if not session:
            return {}

        headers = session.headers.copy()
        headers['Cookie'] = '; '.join(f"{k}={v}" for k, v in session.cookies.items())

        return headers

    def get_token_for_session(self, session_id: Optional[str] = None) -> Optional[str]:
        """Get JWT token for session"""
        session = self.get_session(session_id) if session_id else self.get_active_session()
        return session.jwt_token if session else None

    async def refresh_session(self, session_id: str) -> bool:
        """
        Refresh session token
        """
        session = self._sessions.get(session_id)
        if not session:
            return False

        if session.state == SessionState.REFRESHING:
            logger.warning(f"Session {session_id} already refreshing")
            return False

        session.state = SessionState.REFRESHING

        # Try refresh token first
        if session.refresh_token and self.refresh_endpoint:
            try:
                response = self._http_session.post(
                    urljoin(self.base_url, self.refresh_endpoint),
                    json={"refreshToken": session.refresh_token},
                    timeout=self.timeout
                )

                if response.status_code == 200:
                    data = response.json()
                    new_token = data.get('token') or data.get('accessToken')

                    if new_token:
                        session.jwt_token = new_token
                        session.headers['Authorization'] = f'Bearer {new_token}'
                        session.state = SessionState.ACTIVE
                        session.last_used = time.time()

                        logger.info(f"Session {session_id} refreshed successfully")
                        return True
            except Exception as e:
                logger.error(f"Refresh token error: {e}")

        # Re-authenticate if refresh fails
        logger.info(f"Refresh failed, attempting re-authentication for session {session_id}")
        session.state = SessionState.ACTIVE  # Reset state for re-auth
        return False

    async def check_and_refresh(self, session_id: Optional[str] = None) -> bool:
        """
        Check if session needs refresh and refresh if auto_refresh is enabled
        """
        session = self.get_session(session_id) if session_id else self.get_active_session()

        if not session or not session.jwt_token:
            return False

        # Check if expired
        if session.expires_at and time.time() > session.expires_at:
            session.state = SessionState.EXPIRED
            logger.warning(f"Session {session.session_id} expired")

            if self.auto_refresh:
                return await self.refresh_session(session.session_id)
            return False

        # Check if about to expire
        if session.expires_at and (time.time() + self.token_leeway) > session.expires_at:
            logger.info(f"Session {session.session_id} about to expire, refreshing")

            if self.auto_refresh:
                return await self.refresh_session(session.session_id)

        return True

    def is_session_valid(self, session_id: Optional[str] = None) -> bool:
        """Check if session is valid and active"""
        session = self.get_session(session_id) if session_id else self.get_active_session()

        if not session:
            return False

        if session.state != SessionState.ACTIVE:
            return False

        if session.jwt_token and JWTDecoder.is_expired(session.jwt_token, leeway=self.token_leeway):
            return False

        return True

    def get_user_context(self, session_id: str) -> Dict[str, Any]:
        """Get user context for BOLA testing"""
        session = self.get_session(session_id)
        if not session:
            return {}

        return {
            'session_id': session.session_id,
            'user_id': session.user_id,
            'email': session.email,
            'role': session.role,
            'token': session.jwt_token,
            'headers': self.get_headers_for_session(session_id)
        }

    async def test_bola(
        self,
        url: str,
        session_a_id: str,
        session_b_id: str,
        method: str = "GET",
        data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Test for BOLA/IDOR vulnerability
        Makes same request with both sessions and compares responses
        """
        session_a = self.get_session(session_a_id)
        session_b = self.get_session(session_b_id)

        if not session_a or not session_b:
            return {'vulnerable': False, 'error': 'Session not found'}

        result = {
            'url': url,
            'method': method,
            'user_a': session_a.email,
            'user_b': session_b.email,
            'vulnerable': False,
            'details': {}
        }

        try:
            # Request with User A's token
            headers_a = self.get_headers_for_session(session_a_id)
            resp_a = self._http_session.request(
                method,
                url,
                headers=headers_a,
                json=data if method == "POST" else None,
                params=data if method == "GET" else None,
                timeout=self.timeout,
                verify=False
            )

            # Request with User B's token
            headers_b = self.get_headers_for_session(session_b_id)
            resp_b = self._http_session.request(
                method,
                url,
                headers=headers_b,
                json=data if method == "POST" else None,
                params=data if method == "GET" else None,
                timeout=self.timeout,
                verify=False
            )

            result['details'] = {
                'user_a_status': resp_a.status_code,
                'user_b_status': resp_b.status_code,
                'user_a_length': len(resp_a.text),
                'user_b_length': len(resp_b.text),
            }

            # BOLA detection logic
            # If both get 200 but responses differ in user-specific data
            if resp_a.status_code == 200 and resp_b.status_code == 200:
                try:
                    data_a = resp_a.json()
                    data_b = resp_b.json()

                    # Check if response contains user-specific data
                    user_a_id = session_a.user_id
                    user_b_id = session_b.user_id

                    # Serialize for comparison
                    json_a = json.dumps(data_a, sort_keys=True)
                    json_b = json.dumps(data_b, sort_keys=True)

                    # If responses are identical but should be user-specific
                    if json_a == json_b:
                        result['vulnerable'] = True
                        result['details']['reason'] = 'Identical responses for different users'
                        logger.warning(f"BOLA detected: {url} - identical responses")

                    # Check if User A can access User B's data
                    if user_b_id and str(user_b_id) in json_a:
                        result['vulnerable'] = True
                        result['details']['reason'] = 'User A can access User B data'
                        logger.warning(f"BOLA detected: {url} - cross-user data access")

                except json.JSONDecodeError:
                    # Non-JSON response - compare lengths
                    if len(resp_a.text) == len(resp_b.text):
                        result['details']['note'] = 'Identical response lengths (non-JSON)'

            # If User B gets 403/401 but User A gets 200 - proper authorization
            elif resp_a.status_code == 200 and resp_b.status_code in [401, 403]:
                result['details']['note'] = 'Proper authorization enforced'

            # If both get 401/403 - authentication required
            elif resp_a.status_code in [401, 403] and resp_b.status_code in [401, 403]:
                result['details']['note'] = 'Authentication required for both users'

        except requests.RequestException as e:
            result['error'] = str(e)
            logger.error(f"BOLA test error: {e}")

        return result

    def terminate_session(self, session_id: str):
        """Terminate a session"""
        if session_id in self._sessions:
            self._sessions[session_id].state = SessionState.TERMINATED
            logger.info(f"Session {session_id} terminated")

    def get_all_sessions(self) -> List[SessionData]:
        """Get all sessions"""
        return list(self._sessions.values())

    def cleanup_expired_sessions(self):
        """Remove expired sessions"""
        expired = [
            sid for sid, session in self._sessions.items()
            if session.state in [SessionState.EXPIRED, SessionState.TERMINATED]
        ]

        for sid in expired:
            del self._sessions[sid]
            logger.info(f"Cleaned up expired session {sid}")

        return len(expired)


class SessionContext:
    """Context manager for temporary session usage"""

    def __init__(self, manager: SessionManager, session_id: str):
        self.manager = manager
        self.session_id = session_id
        self._previous_session = manager._active_session_id

    def __enter__(self):
        self.manager.switch_session(self.session_id)
        return self.manager.get_session(self.session_id)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._previous_session:
            self.manager.switch_session(self._previous_session)


if __name__ == "__main__":
    # Test
    async def test_session_manager():
        manager = SessionManager("http://localhost:3000")

        # Create test sessions
        credentials_a = UserCredentials(
            email="admin@juice-sh.op",
            password="admin123",
            role="admin"
        )

        credentials_b = UserCredentials(
            email="user@juice-sh.op",
            password="user123",
            role="user"
        )

        # Authenticate both users
        session_a, session_b = await manager.authenticate_user_a_and_b(
            credentials_a, credentials_b
        )

        if session_a and session_b:
            print(f"User A: {session_a.email} ({session_a.role})")
            print(f"User B: {session_b.email} ({session_b.role})")

            # Test BOLA
            result = await manager.test_bola(
                "http://localhost:3000/api/Address/1",
                session_a.session_id,
                session_b.session_id
            )

            print(f"BOLA Test Result: {result}")

    # asyncio.run(test_session_manager())
    print("SessionManager module loaded")
