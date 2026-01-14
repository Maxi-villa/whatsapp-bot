from flask import Flask, request, jsonify
import requests
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Configuración desde variables de entorno
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "mi_token_secreto_123")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID")
VERSION = "v21.0"

@app.route("/webhook", methods=["GET"])
def verify_webhook():
    """Verificación del webhook por parte de Meta"""
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    
    if mode == "subscribe" and token == VERIFY_TOKEN:
        print("Webhook verificado correctamente")
        return challenge, 200
    else:
        return "Forbidden", 403

@app.route("/webhook", methods=["POST"])
def webhook():
    """Recibe mensajes de WhatsApp"""
    try:
        data = request.get_json()
        print("Mensaje recibido:", data)
        
        # Verificar que sea un mensaje
        if data.get("object") == "whatsapp_business_account":
            entries = data.get("entry", [])
            
            for entry in entries:
                changes = entry.get("changes", [])
                
                for change in changes:
                    value = change.get("value", {})
                    messages = value.get("messages", [])
                    
                    for message in messages:
                        # Obtener datos del mensaje
                        from_number = message.get("from")
                        message_body = message.get("text", {}).get("body", "")
                        message_id = message.get("id")
                        
                        print(f"Mensaje de {from_number}: {message_body}")
                        
                        # Responder al mensaje
                        send_message(from_number, f"Hola! Recibí tu mensaje: '{message_body}'")
        
        return jsonify({"status": "success"}), 200
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

def send_message(to_number, message_text):
    """Envía un mensaje de WhatsApp"""
    url = f"https://graph.facebook.com/{VERSION}/{PHONE_NUMBER_ID}/messages"
    
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json"
    }
    
    data = {
        "messaging_product": "whatsapp",
        "to": to_number,
        "type": "text",
        "text": {"body": message_text}
    }
    
    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            print(f"Mensaje enviado a {to_number}")
        else:
            print(f"Error al enviar mensaje: {response.text}")
        return response
    except Exception as e:
        print(f"Error: {str(e)}")
        return None

@app.route("/")
def home():
    return "WhatsApp Bot está corriendo! 🤖"

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
