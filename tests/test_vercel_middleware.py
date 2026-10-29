import pytest
from urllib.parse import parse_qs, urlencode


class VercelPathMiddleware:
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        query_string = environ.get("QUERY_STRING", "")
        params = parse_qs(query_string, keep_blank_values=True)

        target_path = None
        if "__path__" in params and params["__path__"]:
            target_path = params.pop("__path__")[0]
            if not target_path.startswith("/"):
                target_path = "/" + target_path
            environ["QUERY_STRING"] = urlencode(params, doseq=True)

        if not target_path:
            matched_path = environ.get("HTTP_X_MATCHED_PATH")
            if matched_path and matched_path not in ("/api/index", "/api/index.py", "/api"):
                target_path = matched_path
            else:
                target_path = "/"

        while target_path.startswith("//"):
            target_path = target_path[1:]

        environ["PATH_INFO"] = target_path
        return self.wsgi_app(environ, start_response)


def mock_app(environ, start_response):
    return f"path:{environ['PATH_INFO']},query:{environ.get('QUERY_STRING', '')}"


def test_vercel_middleware_root():
    app = VercelPathMiddleware(mock_app)
    env = {"PATH_INFO": "/api/index", "QUERY_STRING": "__path__=/"}
    res = app(env, None)
    assert env["PATH_INFO"] == "/"
    assert env["QUERY_STRING"] == ""


def test_vercel_middleware_login():
    app = VercelPathMiddleware(mock_app)
    env = {"PATH_INFO": "/api/index", "QUERY_STRING": "__path__=/login"}
    res = app(env, None)
    assert env["PATH_INFO"] == "/login"
    assert env["QUERY_STRING"] == ""


def test_vercel_middleware_with_query_params():
    app = VercelPathMiddleware(mock_app)
    env = {"PATH_INFO": "/api/index", "QUERY_STRING": "__path__=/evidence&type=image&page=2"}
    res = app(env, None)
    assert env["PATH_INFO"] == "/evidence"
    assert "type=image" in env["QUERY_STRING"]
    assert "page=2" in env["QUERY_STRING"]
    assert "__path__" not in env["QUERY_STRING"]


def test_vercel_middleware_fallback():
    app = VercelPathMiddleware(mock_app)
    env = {"PATH_INFO": "/api/index", "QUERY_STRING": "", "HTTP_X_MATCHED_PATH": "/dashboard"}
    res = app(env, None)
    assert env["PATH_INFO"] == "/dashboard"
