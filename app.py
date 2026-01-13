from flask import Flask, request, jsonify
import requests
import os
from dotenv import load_dotenv
import json

load_dotenv()

app = Flask(__name__)

# Configuración desde variables de entorno
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "mi_token_secreto_123")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID")
VERSION = "v21.0"

print("=" * 60)
print("BOT INICIADO - CONFIGURACIÓN:")
print(f"VERIFY_TOKEN: {VERIFY_TOKEN}")
print(f"WHATSAPP_TOKEN configurado: {'Sí' if WHATSAPP_TOKEN else 'NO'}")
print(f"PHONE_NUMBER_ID: {PHONE_NUMBER_ID}")
print("=" * 60)

@app.route("/webhook", methods=["GET"])
def verify_webhook():
    """Verificación del webhook por parte de Meta"""
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    
    print("=" * 60)
    print("VERIFICACIÓN DE WEBHOOK")
    print(f"Mode: {mode}")
    print(f"Token recibido: {token}")
    print(f"Token esperado: {VERIFY_TOKEN}")
    print(f"Challenge: {challenge}")
    print("=" * 60)
    
    if mode == "subscribe" and token == VERIFY_TOKEN:
        print("✅ Webhook verificado correctamente")
        return challenge, 200
    else:
        print("❌ Webhook rechazado - token incorrecto")
        return "Forbidden", 403

@app.route("/webhook", methods=["POST"])
def webhook():
    """Recibe mensajes de WhatsApp"""
    try:
        data = request.get_json()
        
        print("=" * 60)
        print("🔔 MENSAJE RECIBIDO")
        print("Data completa:")
        print(json.dumps(data, indent=2))
        print("=" * 60)
        
        # Verificar que sea un mensaje
        if data.get("object") == "whatsapp_business_account":
            entries = data.get("entry", [])
            print(f"Número de entries: {len(entries)}")
            
            for entry in entries:
                changes = entry.get("changes", [])
                print(f"Número de changes: {len(changes)}")
                
                for change in changes:
                    value = change.get("value", {})
                    messages = value.get("messages", [])
                    print(f"Número de messages: {len(messages)}")
                    
                    for message in messages:
                        # Obtener datos del mensaje
                        from_number = message.get("from")
                        message_body = message.get("text", {}).get("body", "")
                        message_id = message.get("id")
                        
                        print("=" * 60)
                        print(f"📱 Mensaje de: {from_number}")
                        print(f"📝 Contenido: {message_body}")
                        print(f"🆔 ID: {message_id}")
                        print("=" * 60)
                        
                        # Responder al mensaje
                        print(f"Intentando enviar respuesta a {from_number}...")
                        resultado = send_message(from_number, f"Hola! Recibí tu mensaje: '{message_body}'")
                        
                        if resultado and resultado.status_code == 200:
                            print("✅ Mensaje enviado exitosamente")
                        else:
                            print(f"❌ Error al enviar mensaje: {resultado.text if resultado else 'Sin respuesta'}")
        else:
            print(f"❌ Object no reconocido: {data.get('object')}")
        
        return jsonify({"status": "success"}), 200
        
    except Exception as e:
        print("=" * 60)
        print(f"❌ ERROR CRÍTICO: {str(e)}")
        print("=" * 60)
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

def send_message(to_number, message_text):
    """Envía un mensaje de WhatsApp"""
    url = f"https://graph.facebook.com/{VERSION}/{PHONE_NUMBER_ID}/messages"
    
    print("=" * 60)
    print("📤 ENVIANDO MENSAJE")
    print(f"URL: {url}")
    print(f"A: {to_number}")
    print(f"Mensaje: {message_text}")
    print("=" * 60)
    
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
        print(f"Status Code: {response.status_code}")
        print(f"Respuesta: {response.text}")
        return response
    except Exception as e:
        print(f"❌ Error en send_message: {str(e)}")
        return None

@app.route("/")
def home():
    return "WhatsApp Bot está corriendo! 🤖"

@app.route("/test")
def test():
    """Endpoint de prueba para verificar configuración"""
    return jsonify({
        "status": "ok",
        "verify_token_configurado": bool(VERIFY_TOKEN),
        "whatsapp_token_configurado": bool(WHATSAPP_TOKEN),
        "phone_id_configurado": bool(PHONE_NUMBER_ID)
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)