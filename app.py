# app.py
import os
import hmac
import hashlib
import json
import logging
import threading
import requests
from flask import Flask, request, abort

# =========================
# APP SETUP
# =========================
app = Flask(__name__)

# =========================
# ENV CONFIG (Railway)
# =========================
VERIFY_TOKEN = os.environ.get("VERIFY_TOKEN", "mi_token_secreto_123")
APP_SECRET = os.environ.get("APP_SECRET", "")  # opcional (HMAC)
WHATSAPP_TOKEN = os.environ.get("WHATSAPP_TOKEN", "")
PHONE_NUMBER_ID = os.environ.get("PHONE_NUMBER_ID", "1031534173366600")

GRAPH_API_BASE = "https://graph.facebook.com/v21.0"

# =========================
# LOGGING
# =========================
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("whatsapp_bot")

# =========================
# SECURITY
# =========================
def verify_signature(raw_body: bytes, header_signature: str) -> bool:
    """
    Valida X-Hub-Signature-256 si APP_SECRET está configurado.
    En test, si no hay APP_SECRET, no bloquea.
    """
    if not APP_SECRET:
        return True
    if not header_signature:
        return False

    expected = "sha256=" + hmac.new(
        APP_SECRET.encode(),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, header_signature)

# =========================
# WHATSAPP SEND
# =========================
def send_whatsapp_message(to: str, text: str):
    """
    Envía mensaje de texto por WhatsApp Cloud API
    """
    url = f"{GRAPH_API_BASE}/{PHONE_NUMBER_ID}/messages"
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

    try:
        resp = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=5
        )

        logger.info("📤 Enviando mensaje a %s", to)
        logger.info("Status: %s", resp.status_code)

        try:
            logger.debug("Respuesta JSON: %s", resp.json())
        except Exception:
            logger.debug("Respuesta texto: %s", resp.text)

        if resp.status_code not in (200, 201):
            try:
                err = resp.json().get("error", {})
                if err.get("code") == 131030:
                    logger.warning(
                        "Recipient not allowed (131030). "
                        "Agregar número a allowlist si usás Test Number."
                    )
            except Exception:
                pass

        return resp.status_code

    except Exception as e:
        logger.exception("❌ Error enviando mensaje: %s", e)
        return None

# =========================
# PROCESS INCOMING
# =========================
def process_incoming(data: dict):
    """
    Procesa mensajes entrantes.
    Filtra eventos irrelevantes y evita loops.
    """
    try:
        entries = data.get("entry", [])

        for entry in entries:
            for change in entry.get("changes", []):
                value = change.get("value", {})

                # Ignorar eventos sin mensajes
                messages = value.get("messages")
                if not messages:
                    continue

                metadata = value.get("metadata", {})
                business_phone_id = metadata.get("phone_number_id")

                for msg in messages:
                    from_id = msg.get("from")
                    msg_id = msg.get("id")
                    msg_type = msg.get("type")

                    # Evitar responder a nuestros propios mensajes
                    if from_id == business_phone_id:
                        continue

                    if msg_type != "text":
                        continue

                    body = msg.get("text", {}).get("body", "")

                    logger.info("📩 Mensaje recibido")
                    logger.info("De: %s", from_id)
                    logger.info("ID: %s", msg_id)
                    logger.info("Texto: %s", body)

                    reply = f"Hola! Recibí tu mensaje: '{body}'"
                    send_whatsapp_message(from_id, reply)

    except Exception:
        logger.exception("❌ Error procesando mensaje entrante")

# =========================
# WEBHOOK
# =========================
@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    # ---- GET: Verificación ----
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        logger.debug("🔐 Verificación webhook")
        logger.debug("Mode: %s", mode)
        logger.debug("Token recibido: %s", token)

        if mode == "subscribe" and token == VERIFY_TOKEN:
            return challenge or "", 200

        return "Forbidden", 403

    # ---- POST: Eventos ----
    raw = request.get_data()
    signature = request.headers.get("X-Hub-Signature-256", "")

    if not verify_signature(raw, signature):
        logger.warning("❌ Firma inválida")
        abort(403)

    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as e:
        logger.error("❌ JSON inválido: %s", e)
        return "Bad Request", 400

    # Procesar en background
    threading.Thread(
        target=process_incoming,
        args=(data,),
        daemon=True
    ).start()

    return "", 200

# =========================
# HEALTHCHECK
# =========================
@app.route("/", methods=["GET"])
def index():
    return "OK", 200

# =========================
# LOCAL RUN
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
