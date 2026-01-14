# app.py (mejorado)
import os
import hmac
import hashlib
import json
import logging
import threading
import requests
from flask import Flask, request, abort, jsonify

app = Flask(__name__)

# CONFIG
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "mi_token_secreto_123")
APP_SECRET = os.getenv("APP_SECRET", "")          # opcional
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID", "")
GRAPH_VERSION = "v24.0"  # usar la versión actual

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("whatsapp_bot")

def verify_signature(raw_body: bytes, header_signature: str) -> bool:
    if not APP_SECRET:
        return True
    if not header_signature:
        return False
    expected = "sha256=" + hmac.new(APP_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header_signature)

def send_message(to_number: str, text: str):
    if not WHATSAPP_TOKEN or not PHONE_NUMBER_ID:
        logger.error("Falta WHATSAPP_TOKEN o PHONE_NUMBER_ID en variables de entorno")
        return None

    url = f"https://graph.facebook.com/{GRAPH_VERSION}/{PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_number,
        "type": "text",
        "text": {"body": text}
    }
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=6)
        logger.info("Enviando mensaje a %s — status %s", to_number, resp.status_code)
        try:
            logger.debug("Respuesta API: %s", resp.json())
        except Exception:
            logger.debug("Respuesta API text: %s", resp.text)
        if resp.status_code not in (200,201):
            logger.warning("Error al enviar mensaje: %s", resp.text)
        return resp
    except Exception as e:
        logger.exception("Exception enviando mensaje: %s", e)
        return None

def process_payload(data):
    entries = data.get("entry", [])
    for entry in entries:
        for change in entry.get("changes", []):
            value = change.get("value", {})
            messages = value.get("messages")
            if not messages:
                continue
            metadata = value.get("metadata", {})
            phone_id = metadata.get("phone_number_id")
            for msg in messages:
                from_num = msg.get("from")
                msg_type = msg.get("type")
                if msg_type != "text":
                    logger.info("Ignorando tipo %s", msg_type)
                    continue
                body = msg.get("text", {}).get("body", "")
                logger.info("📩 Mensaje de: %s — %s", from_num, body)

                # Evitar responder a sí mismo (no es always necessary)
                if phone_id and from_num == phone_id:
                    logger.info("Mensaje desde el mismo phone_number_id, salto para evitar loop")
                    continue

                # Generar respuesta simple
                reply = f"Hola! Recibí tu mensaje: '{body}'"
                resp = send_message(from_num, reply)
                if resp is not None and resp.status_code in (200,201):
                    logger.info("Respuesta enviada correctamente a %s", from_num)
                else:
                    logger.warning("No se pudo enviar respuesta a %s", from_num)

@app.route("/webhook", methods=["GET","POST"])
def webhook():
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")
        logger.debug("Verificación webhook: mode=%s token=%s", mode, token)
        if mode == "subscribe" and token == VERIFY_TOKEN:
            return challenge or "", 200
        return "Forbidden", 403

    # POST
    raw = request.get_data()
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not verify_signature(raw, signature):
        logger.warning("Firma inválida")
        abort(403)

    try:
        # intentar parsear incluso si Content-Type falta
        data = json.loads(raw.decode("utf-8"))
    except Exception as e:
        logger.error("No se pudo parsear JSON: %s", e)
        return "Bad Request - invalid JSON", 400

    # responder 200 y procesar en background
    threading.Thread(target=process_payload, args=(data,), daemon=True).start()
    return jsonify({"status":"received"}), 200

@app.route("/")
def index():
    return "OK", 200

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
