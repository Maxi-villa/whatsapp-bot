# app.py
import os
import hmac
import hashlib
import json
import logging
import threading
import requests
import time
import uuid
from datetime import datetime
from flask import Flask, request, abort, jsonify

# --------------------
# Config / env
# --------------------
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "mi_token_secreto_123")
APP_SECRET = os.getenv("APP_SECRET", "")           # opcional
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID", "")
GRAPH_VERSION = os.getenv("GRAPH_VERSION", "v24.0")

# --------------------
# Logging - very verbose
# --------------------
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("whatsapp_bot_verbose")

def now():
    return datetime.utcnow().isoformat() + "Z"

def mask_token(t):
    if not t:
        return "<empty>"
    if len(t) <= 10:
        return t
    return t[:6] + "..." + t[-6:]

logger.info("ARRANQUE: whatsapp_bot_verbose - %s", now())
logger.info("ENV: PHONE_NUMBER_ID=%s, WHATSAPP_TOKEN=%s, VERIFY_TOKEN=%s, APP_SECRET set=%s",
            PHONE_NUMBER_ID or "<empty>",
            mask_token(WHATSAPP_TOKEN),
            VERIFY_TOKEN or "<empty>",
            bool(APP_SECRET))

app = Flask(__name__)

# --------------------
# Helpers
# --------------------
def generate_correlation_id():
    return str(uuid.uuid4())

def verify_signature(raw_body: bytes, header_signature: str) -> bool:
    logger.debug("verify_signature: header present=%s, APP_SECRET set=%s", bool(header_signature), bool(APP_SECRET))
    if not APP_SECRET:
        logger.debug("verify_signature: no APP_SECRET configured -> skipping validation")
        return True
    if not header_signature:
        logger.warning("verify_signature: X-Hub-Signature-256 missing")
        return False
    expected = "sha256=" + hmac.new(APP_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    ok = hmac.compare_digest(expected, header_signature)
    logger.debug("verify_signature: computed=%s header=%s match=%s", expected, header_signature, ok)
    return ok

def send_whatsapp_message(to: str, text: str, corr_id: str):
    """
    Envía mensaje a Graph API y logea TODO. Devuelve (status_code, text, json_or_None)
    """
    url = f"https://graph.facebook.com/{GRAPH_VERSION}/{PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": text}
    }
    logger.info("[%s] SEND: url=%s to=%s payload=%s", corr_id, url, to, json.dumps(payload, ensure_ascii=False))
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=8)
        logger.info("[%s] SEND_RESP: status=%s", corr_id, resp.status_code)
        try:
            j = resp.json()
            logger.debug("[%s] SEND_RESP_JSON: %s", corr_id, json.dumps(j, ensure_ascii=False))
        except Exception as e:
            logger.debug("[%s] SEND_RESP_TEXT: %s (json parse error: %s)", corr_id, resp.text, e)
            j = None
        if resp.status_code not in (200, 201):
            logger.warning("[%s] SEND_ERROR: %s", corr_id, resp.text)
        return resp.status_code, resp.text, j
    except Exception as e:
        logger.exception("[%s] Exception sending message: %s", corr_id, e)
        return None, str(e), None

# --------------------
# Processing (background)
# --------------------
def process_incoming(data: dict, corr_id: str):
    start_ts = time.time()
    logger.info("[%s] process_incoming START - entries=%s", corr_id, len(data.get("entry", [])))
    try:
        entries = data.get("entry", [])
        for ei, entry in enumerate(entries):
            logger.debug("[%s] entry[%s] keys=%s", corr_id, ei, list(entry.keys()))
            changes = entry.get("changes", [])
            for ci, change in enumerate(changes):
                logger.debug("[%s] entry[%s].change[%s] keys=%s", corr_id, ei, ci, list(change.keys()))
                field = change.get("field")
                logger.debug("[%s] change.field=%s", corr_id, field)
                value = change.get("value", {})
                # full dump of value size limited
                try:
                    logger.debug("[%s] value (trim)=%s", corr_id, json.dumps(value)[:2000])
                except Exception:
                    logger.debug("[%s] value (raw) could not json dump", corr_id)
                # messages
                messages = value.get("messages") or []
                if not messages:
                    logger.info("[%s] No messages in change -> skip", corr_id)
                    continue
                metadata = value.get("metadata", {})
                phone_id = metadata.get("phone_number_id")
                display_phone = metadata.get("display_phone_number")
                logger.info("[%s] Metadata: phone_id=%s display_phone=%s", corr_id, phone_id, display_phone)
                for mi, msg in enumerate(messages):
                    logger.info("[%s] message[%s] keys=%s", corr_id, mi, list(msg.keys()))
                    from_num = msg.get("from")
                    mid = msg.get("id")
                    mtype = msg.get("type")
                    text_body = ""
                    if mtype == "text":
                        text_body = msg.get("text", {}).get("body", "")
                    logger.info("[%s] Mensaje recibido: from=%s id=%s type=%s body=%s", corr_id, from_num, mid, mtype, text_body)
                    # safety checks
                    if not from_num:
                        logger.warning("[%s] Mensaje sin campo 'from' -> skip", corr_id)
                        continue
                    # avoid loop: if from equals phone_id (string numbers), skip
                    if phone_id and str(from_num).endswith(str(phone_id)):
                        # rarely matches, but defensive
                        logger.info("[%s] Avoid loop: from looks like phone_id -> skip", corr_id)
                        continue
                    # Reply text
                    reply = f"Hola! Recibí tu mensaje: '{text_body}' (corr_id={corr_id})"
                    scode, stext, sjson = send_whatsapp_message(from_num, reply, corr_id)
                    logger.info("[%s] send result: status=%s", corr_id, scode)
    except Exception as e:
        logger.exception("[%s] Exception in process_incoming: %s", corr_id, e)
    finally:
        dt = time.time() - start_ts
        logger.info("[%s] process_incoming END (took %.3fs)", corr_id, dt)

# --------------------
# BEFORE REQUEST - log everything
# --------------------
@app.before_request
def log_request():
    corr_id = request.headers.get("X-Correlation-Id") or generate_correlation_id()
    request.environ["corr_id"] = corr_id
    logger.debug("[%s] REQUEST START %s %s", corr_id, request.method, request.path)
    try:
        logger.debug("[%s] Remote Addr: %s", corr_id, request.remote_addr)
        # full forwarded info
        logger.debug("[%s] X-Forwarded-For: %s", corr_id, request.headers.get("X-Forwarded-For"))
        # headers
        for k, v in request.headers.items():
            logger.debug("[%s] HEADER: %s: %s", corr_id, k, v)
        raw = request.get_data()
        if raw:
            try:
                logger.debug("[%s] RAW_BODY (first1000): %s", corr_id, raw[:1000].decode("utf-8", errors="replace"))
            except Exception:
                logger.debug("[%s] RAW_BODY non-decodable", corr_id)
        else:
            logger.debug("[%s] RAW_BODY empty", corr_id)
    except Exception as e:
        logger.exception("error logging request: %s", e)

# --------------------
# WEBHOOK Endpoint
# --------------------
@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    corr_id = request.environ.get("corr_id") or generate_correlation_id()
    logger.info("[%s] /webhook called method=%s", corr_id, request.method)

    # GET verification
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")
        logger.info("[%s] VERIFY GET: mode=%s token_received=%s expected=%s challenge=%s",
                    corr_id, mode, token, VERIFY_TOKEN, challenge)
        if mode == "subscribe" and token == VERIFY_TOKEN:
            logger.info("[%s] VERIFY OK - returning challenge", corr_id)
            return challenge or "", 200
        logger.warning("[%s] VERIFY FAILED - returning 403", corr_id)
        return "Forbidden", 403

    # POST handling
    raw = request.get_data() or b""
    header_sig = request.headers.get("X-Hub-Signature-256", "")
    logger.info("[%s] POST webhook - content-length=%s signature_present=%s", corr_id, len(raw), bool(header_sig))

    # validate signature if APP_SECRET configured
    try:
        if not verify_signature(raw, header_sig):
            logger.warning("[%s] Signature invalid -> 403", corr_id)
            return "Forbidden - invalid signature", 403
    except Exception as e:
        logger.exception("[%s] Error verifying signature: %s", corr_id, e)
        return "Forbidden - signature error", 403

    # Attempt to parse JSON in several ways
    data = None
    parse_attempts = []
    try:
        parse_attempts.append(("get_json", request.get_json(silent=True)))
    except Exception as e:
        parse_attempts.append(("get_json_exc", str(e)))
    try:
        if not parse_attempts[-1][1]:
            parse_attempts.append(("json_loads_raw", json.loads(raw.decode("utf-8")) if raw else None))
    except Exception as e:
        parse_attempts.append(("json_loads_exc", str(e)))
    try:
        if not parse_attempts[-1][1]:
            # fallback: try to replace single quotes etc
            s = raw.decode("utf-8", errors="replace").strip()
            if s:
                parse_attempts.append(("eval_like", s[:1000]))
    except Exception as e:
        parse_attempts.append(("eval_like_exc", str(e)))

    logger.debug("[%s] parse_attempts: %s", corr_id, parse_attempts[:10])
    # choose first successful
    for key, val in parse_attempts:
        if isinstance(val, dict):
            data = val
            logger.debug("[%s] using parse result from %s", corr_id, key)
            break

    if data is None:
        # If still none, try a last manual naive attempt
        try:
            text = raw.decode("utf-8", errors="replace")
            data = json.loads(text) if text else {}
            logger.debug("[%s] manual json.loads succeeded", corr_id)
        except Exception as e:
            logger.error("[%s] Unable to parse JSON payload: %s", corr_id, e)
            logger.debug("[%s] RAW_BODY for debugging: %s", corr_id, raw[:2000])
            return "Bad Request - invalid JSON", 400

    # final sanity log
    try:
        logger.info("[%s] Mensaje recibido: %s", corr_id, json.dumps(data)[:4000])
    except Exception:
        logger.info("[%s] Mensaje recibido (non-json repr)", corr_id)

    # handle in background and return 200 immediately
    try:
        t = threading.Thread(target=process_incoming, args=(data, corr_id), daemon=True)
        t.start()
        logger.info("[%s] background thread started: %s", corr_id, t.name)
    except Exception as e:
        logger.exception("[%s] could not start background thread: %s", corr_id, e)
        return "Internal Server Error", 500

    return jsonify({"status": "accepted", "corr_id": corr_id}), 200

# --------------------
# HEALTH & DEBUG endpoints
# --------------------
@app.route("/", methods=["GET"])
def index():
    return "OK - " + now(), 200

@app.route("/debug/env", methods=["GET"])
def debug_env():
    # DO NOT expose tokens in production. This is for debugging in dev only.
    envs = {
        "PHONE_NUMBER_ID": PHONE_NUMBER_ID,
        "VERIFY_TOKEN": VERIFY_TOKEN,
        "WHATSAPP_TOKEN_masked": mask_token(WHATSAPP_TOKEN),
        "APP_SECRET_set": bool(APP_SECRET),
        "GRAPH_VERSION": GRAPH_VERSION
    }
    return jsonify(envs), 200

# --------------------
# RUN (local)
# --------------------
if __name__ == "__main__":
    logger.info("Starting app locally on port %s", os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)), debug=False)
