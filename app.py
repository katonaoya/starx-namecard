import hashlib
import hmac
import json
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

import requests
from urllib.parse import urlparse
from flask import Flask, request, jsonify, abort
from dotenv import load_dotenv


# Load .env when running locally. On Render, environment variables are set in the dashboard.
load_dotenv()

# Enable INFO level logging for better observability in production logs
logging.basicConfig(level=logging.INFO)


# Environment variables
SLACK_BOT_TOKEN: Optional[str] = os.getenv("SLACK_BOT_TOKEN")
SLACK_SIGNING_SECRET: Optional[str] = os.getenv("SLACK_SIGNING_SECRET")
DIFY_API_KEY: Optional[str] = os.getenv("DIFY_API_KEY")
DIFY_API_URL: Optional[str] = os.getenv("DIFY_API_URL")  # e.g., https://api.dify.ai/v1/files/upload


# --- Safe HTTP logging helpers (redact secrets, summarize payloads) ---
def _redact_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    safe_headers: Dict[str, str] = dict(headers or {})
    auth_value = safe_headers.get("Authorization")
    if isinstance(auth_value, str):
        # Mask token content while keeping type hint (e.g., "Bearer app-xxxx…")
        try:
            parts = auth_value.split()
            if len(parts) == 2:
                token_prefix, token_value = parts[0], parts[1]
                masked = token_value[:10] + "…(redacted)" if len(token_value) > 10 else "…(redacted)"
                safe_headers["Authorization"] = f"{token_prefix} {masked}"
            else:
                safe_headers["Authorization"] = "…(redacted)"
        except Exception:
            safe_headers["Authorization"] = "…(redacted)"
    return safe_headers


def _log_http_request(method: str, url: str, *, headers=None, params=None, data=None, files=None) -> None:
    filename: Optional[str] = None
    mime_type: Optional[str] = None
    size_desc: str = "unknown"
    try:
        if files and isinstance(files, dict) and "file" in files:
            file_field = files["file"]
            if isinstance(file_field, tuple) and len(file_field) >= 2:
                filename = file_field[0]
                file_obj_or_bytes = file_field[1]
                # file_obj_or_bytes can be bytes or a file-like object
                try:
                    if isinstance(file_obj_or_bytes, (bytes, bytearray)):
                        size_desc = str(len(file_obj_or_bytes))
                    else:
                        # Try to get size from file-like object
                        current_pos = getattr(file_obj_or_bytes, "tell", lambda: None)()
                        seek = getattr(file_obj_or_bytes, "seek", None)
                        if seek is not None and current_pos is not None:
                            seek(0, 2)
                            end_pos = getattr(file_obj_or_bytes, "tell", lambda: None)()
                            size_desc = str(end_pos) if end_pos is not None else "unknown"
                            seek(current_pos, 0)
                except Exception:
                    size_desc = "unknown"
                if len(file_field) >= 3:
                    mime_type = file_field[2]
    except Exception:
        pass
    logging.info(
        f"HTTP {method} {url} params={params} headers={_redact_headers(headers)} file=({filename}, {mime_type}, size={size_desc})"
    )


def _log_http_response(resp) -> None:
    try:
        body = resp.text
        if body and len(body) > 500:
            body = body[:500] + "...(truncated)"
    except Exception:
        body = "<non-text body>"
    try:
        req = resp.request
        logging.info(f"HTTP {getattr(req, 'method', 'UNKNOWN')} {getattr(req, 'url', 'UNKNOWN')} -> {resp.status_code} body={body}")
    except Exception:
        logging.info(f"HTTP (unknown) -> {resp.status_code} body={body}")


def _log_http_request_json(method: str, url: str, *, headers=None, json_body=None) -> None:
    try:
        preview = None
        if json_body is not None:
            text = str(json_body)
            preview = text[:800] + "...(truncated)" if len(text) > 800 else text
    except Exception:
        preview = "<unprintable>"
    logging.info(
        f"HTTP {method} {url} headers={_redact_headers(headers)} json={preview}"
    )


# Basic validation
if not SLACK_BOT_TOKEN:
    logging.warning("SLACK_BOT_TOKEN is not set. Slack Web API calls will fail.")
if not DIFY_API_KEY:
    logging.warning("DIFY_API_KEY is not set. Uploads to Dify will fail.")
if not DIFY_API_URL:
    logging.warning("DIFY_API_URL is not set. Please configure the Dify upload endpoint.")
if not SLACK_SIGNING_SECRET:
    logging.warning("SLACK_SIGNING_SECRET is not set. Request signature verification is disabled.")


app = Flask(__name__)


@app.route("/healthz", methods=["GET"])  # Simple health check
def healthz():
    return jsonify({"status": "ok"})


@app.route("/", methods=["GET"])  # Root landing
def root():
    return jsonify({"message": "Slack Dify Bot is running.", "endpoints": ["/slack/events", "/healthz"]})


def is_request_verified(req) -> bool:
    """Verify Slack request with signing secret if provided.

    Slack doc: https://api.slack.com/authentication/verifying-requests-from-slack
    """
    if not SLACK_SIGNING_SECRET:
        # If not configured, skip verification (not recommended for production)
        return True

    timestamp = req.headers.get("X-Slack-Request-Timestamp", "")
    slack_signature = req.headers.get("X-Slack-Signature", "")

    # Prevent replay attacks: allow only requests within 5 minutes
    try:
        if abs(time.time() - int(timestamp)) > 60 * 5:
            return False
    except ValueError:
        return False

    sig_basestring = f"v0:{timestamp}:{req.get_data(as_text=True)}".encode("utf-8")
    my_signature = (
        "v0="
        + hmac.new(SLACK_SIGNING_SECRET.encode("utf-8"), sig_basestring, hashlib.sha256).hexdigest()
    )
    return hmac.compare_digest(my_signature, slack_signature)


@app.route("/slack/events", methods=["POST"])  # Slack Events API endpoint
def slack_events():
    if not is_request_verified(request):
        abort(401)

    data = request.get_json(silent=True) or {}

    # URL verification challenge
    if data.get("type") == "url_verification":
        return jsonify({"challenge": data.get("challenge", "")})

    # Acknowledge immediately to avoid Slack retries
    acknowledged_response = jsonify({"status": "ok"})

    event: Dict[str, Any] = data.get("event", {})
    if not event:
        return acknowledged_response

    # Process only app_mention events per the spec
    if event.get("type") == "app_mention":
        # Process in background to return 200 fast
        threading.Thread(target=handle_app_mention_event, args=(event,), daemon=True).start()

    return acknowledged_response


def handle_app_mention_event(event: Dict[str, Any]) -> None:
    """Handle app_mention: fetch attached images (files) and send to Dify.

    Strategy:
    1) If files are present directly in the event, use them.
    2) Otherwise, fetch the message via conversations.history or replies using channel + ts.
    """
    channel_id: Optional[str] = event.get("channel")
    slack_user_id: Optional[str] = event.get("user")  # Slackの発言者（ワークフローAPIの user に渡す）
    event_ts: Optional[str] = event.get("ts")

    files: List[Dict[str, Any]] = []
    if isinstance(event.get("files"), list):
        files = event["files"]
    else:
        # fallback: get message by ts to see if files exist
        message = fetch_message_by_ts(channel_id, event_ts)
        if message and isinstance(message.get("files"), list):
            files = message["files"]

    if not files:
        logging.info("No files found in the mention event.")
        return

    for file_obj in files:
        file_id = file_obj.get("id")
        if not file_id:
            continue

        try:
            file_bytes, filename, mime_type = download_slack_file(file_id)
        except Exception as e:
            logging.exception(f"Failed to download Slack file {file_id}: {e}")
            continue

        try:
            status_code, uploaded_file_id = upload_to_dify(file_bytes, filename=filename, mime_type=mime_type)
            logging.info(f"Uploaded to Dify. Status: {status_code}")
            if uploaded_file_id:
                try:
                    wf_status = run_workflow_with_uploaded_file(uploaded_file_id, user=slack_user_id)
                    logging.info(f"Workflow run finished. Status: {wf_status}")
                except Exception as run_e:
                    logging.exception(f"Failed to run workflow for uploaded file {uploaded_file_id}: {run_e}")
        except Exception as e:
            logging.exception(f"Failed to upload to Dify for file {file_id}: {e}")


def fetch_message_by_ts(channel_id: Optional[str], ts: Optional[str]) -> Optional[Dict[str, Any]]:
    if not SLACK_BOT_TOKEN or not channel_id or not ts:
        return None

    headers = {"Authorization": f"Bearer {SLACK_BOT_TOKEN}"}
    # conversations.history with latest and inclusive to fetch exact message
    params = {
        "channel": channel_id,
        "latest": ts,
        "inclusive": True,
        "limit": 1,
    }
    _log_http_request(
        "GET",
        "https://slack.com/api/conversations.history",
        headers=headers,
        params=params,
    )
    resp = requests.get("https://slack.com/api/conversations.history", headers=headers, params=params, timeout=20)
    _log_http_response(resp)
    data = resp.json()
    if not data.get("ok"):
        logging.warning(f"conversations.history failed: {data}")
        return None
    messages = data.get("messages") or []
    if not messages:
        return None
    return messages[0]


def download_slack_file(file_id: str) -> tuple[bytes, str, str]:
    if not SLACK_BOT_TOKEN:
        raise RuntimeError("SLACK_BOT_TOKEN is not configured")

    headers = {"Authorization": f"Bearer {SLACK_BOT_TOKEN}"}

    _log_http_request(
        "GET",
        "https://slack.com/api/files.info",
        headers=headers,
        params={"file": file_id},
    )
    info_resp = requests.get(
        "https://slack.com/api/files.info",
        headers=headers,
        params={"file": file_id},
        timeout=20,
    )
    _log_http_response(info_resp)
    info = info_resp.json()
    if not info.get("ok"):
        raise RuntimeError(f"files.info failed: {info}")

    file_obj = info.get("file", {})
    download_url = file_obj.get("url_private_download")
    mime_type = file_obj.get("mimetype") or "application/octet-stream"
    name = file_obj.get("name") or f"file_{file_id}"

    if not download_url:
        raise RuntimeError("url_private_download not available")

    _log_http_request("GET", download_url, headers=headers)
    bin_resp = requests.get(download_url, headers=headers, timeout=60)
    bin_resp.raise_for_status()
    try:
        content_len = len(bin_resp.content)
    except Exception:
        content_len = "unknown"
    logging.info(f"HTTP GET {download_url} -> {bin_resp.status_code} content_length={content_len}")
    return bin_resp.content, name, mime_type


def upload_to_dify(file_bytes: bytes, filename: str = "image.jpg", mime_type: str = "image/jpeg") -> tuple[int, Optional[str]]:
    if not (DIFY_API_KEY and DIFY_API_URL):
        raise RuntimeError("DIFY_API_KEY or DIFY_API_URL not configured")

    headers = {
        "Authorization": f"Bearer {DIFY_API_KEY}",
    }
    files = {
        "file": (filename, file_bytes, mime_type),
    }
    data = {}

    _log_http_request(
        "POST",
        DIFY_API_URL,
        headers=headers,
        files=files,
        data=data,
    )
    resp = requests.post(DIFY_API_URL, headers=headers, files=files, data=data, timeout=120)
    _log_http_response(resp)
    try:
        logging.info(f"Dify response: status={resp.status_code} body={resp.text}")
    except Exception:
        pass
    uploaded_file_id: Optional[str] = None
    try:
        body_json = resp.json()
        if isinstance(body_json, dict):
            uploaded_file_id = body_json.get("id")
    except Exception:
        uploaded_file_id = None
    return resp.status_code, uploaded_file_id


def run_workflow_with_uploaded_file(file_id: str, *, user: Optional[str] = None) -> int:
    """Run the Dify workflow by passing uploaded file to start node input `card_images`.

    Uses the base URL derived from DIFY_API_URL (upload endpoint) and calls /v1/workflows/run.
    """
    if not (DIFY_API_KEY and DIFY_API_URL):
        raise RuntimeError("DIFY_API_KEY or DIFY_API_URL not configured")

    try:
        parsed = urlparse(DIFY_API_URL)
        base = f"{parsed.scheme}://{parsed.netloc}"
    except Exception as e:
        raise RuntimeError(f"Failed to parse DIFY_API_URL: {e}")

    workflows_run_url = f"{base}/v1/workflows/run"

    payload: Dict[str, Any] = {
        "inputs": {
            "card_images": [
                {
                    "upload_file_id": file_id,
                    "type": "image",
                    "transfer_method": "local_file",
                }
            ]
        },
        "response_mode": "blocking",
    }
    if user:
        payload["user"] = user

    headers = {
        "Authorization": f"Bearer {DIFY_API_KEY}",
        "Content-Type": "application/json",
    }

    _log_http_request_json("POST", workflows_run_url, headers=headers, json_body=payload)
    resp = requests.post(workflows_run_url, headers=headers, json=payload, timeout=120)
    _log_http_response(resp)
    return resp.status_code


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    # 0.0.0.0 for Render / Docker
    app.run(host="0.0.0.0", port=port)


