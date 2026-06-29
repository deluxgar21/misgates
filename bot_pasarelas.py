import logging
import time
import httpx
import threading
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Configuración de Logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'es-ES,es;q=0.9',
    'Connection': 'keep-alive'
}

def detectar_por_estructura(url, html, headers):
    pasarelas = set()
    url_low = url.lower()
    html_low = html.lower()
    headers_str = str(headers).lower()
    
    if "stripe" in headers_str: pasarelas.add('Stripe')
    if "paypal" in headers_str: pasarelas.add('Paypal')

    firmas = {
        'Stripe': ['://stripe.com', 'stripe-checkout', 'v3.stripe', 'stripe.js', 'stripe-v3', 'data-stripe', 'paymentelement'],
        'Paypal': ['://paypal.com', 'paypal-button', '://paypalobjects.com', 'paypalinc', 'paypal_express', 'give with paypal', 'paypal'],
        'Braintree': ['braintree-api', 'braintreegateway', 'braintree.js'],
        'WooCommerce': ['woocommerce', 'wp-content/plugins/woocommerce', 'wc-ajax'],
        'Shopify': ['shopify-pay', '://shopify.com', 'shopify-checkout'],
        'MercadoPago': ['mercadopago.js', '://mercadopago.com', 'mp-buttons'],
        'Square': ['squareup.com', 'square.js', 'sq-payment-form'],
        'Authorize.Net': ['authorizenet', 'accept.js.authorize.net'],
        'Engiven': ['engiven', 'give crypto', 'give stock']
    }
    
    for pasarela, palabras in firmas.items():
        if any(p in html_low for p in palabras):
            pasarelas.add(pasarela)

    if "giving" in url_low or "donate" in url_low:
        if "paypal" in html_low or not pasarelas: pasarelas.add('Paypal')
        if "crypto" in html_low or "engiven" in html_low: pasarelas.add('Engiven')
        if "credit" in html_low or "card" in html_low: pasarelas.add('Stripe')

    if "stripe" in html_low or "stripe" in url_low: pasarelas.add('Stripe')
    if "wp-content" in html_low or "woocommerce" in html_low: pasarelas.add('WooCommerce')

    return sorted(list(pasarelas)) if pasarelas else ["Not Detected"]

async def analizar_sitio_pro(url):
    if not url.startswith('http'):
        url = 'https://' + url

    html = ""
    status = "Unknown"
    headers_servidor = {}
    size = 0
    inicio_tiempo = time.time()

    async with httpx.AsyncClient(headers=HEADERS, verify=False, follow_redirects=True, timeout=10.0) as client:
        try:
            respuesta = await client.get(url)
            status = respuesta.status_code
            html = respuesta.text
            headers_servidor = respuesta.headers
            size = len(respuesta.content)
        except Exception:
            status = "Bloqueado / Error de red"
            html = ""
            size = 0

    tiempo_respuesta = round(time.time() - inicio_tiempo, 2)
    redir = "None"
    
    has_csp = "True" if "content-security-policy" in headers_servidor else "False"
    has_hsts = "True" if "strict-transport-security" in headers_servidor else "False"
    xfo = headers_servidor.get("x-frame-options", "None")
    xcto = headers_servidor.get("x-content-type-options", "None")
    
    server_header = headers_servidor.get("server", "").lower()
    cloudflare = "Detected" if "cloudflare" in server_header or "cf-ray" in headers_servidor else "None"
    
    captcha = "None"
    html_low = html.lower() if html else ""
    if "recaptcha" in html_low: captcha = "recaptcha"

    campos = []
    if html:
        if any(x in html_low for x in ["card", "numero", "credit", "payment"]): campos.append("card")
        if any(x in html_low for x in ["address", "direccion", "zip", "postal"]): campos.append("address")
        if any(x in html_low for x in ["name", "nombre", "first", "email"]): campos.append("name")
    campos_str = ", ".join(campos) if campos else "Unknown"

    security_3d = "3D Secure (Detected)" if "3ds" in html_low else "2D (No 3D Secure Found)"
    
    if html:
        gateways = ", ".join(detectar_por_estructura(url, html, headers_servidor))
        tamano_kb = round(size / 1024, 2)
    else:
        gateways = "No Detectado (El sitio bloqueó al servidor)"
        tamano_kb = 0

    mensaje = (
        f" [⌬] <b>𝐒𝐢𝐭e</b> ➔ {url}\n"
        f" [⌬] <b>𝐑e𝐝𝐢𝐫e𝐜𝐭𝐬</b> ➔ {redir}\n"
        f" [⌬] <b>𝐒e𝐜𝐮𝐫𝐢𝐭𝐲 𝐇e𝐚𝐝e𝐫𝐬</b> ➔ CSP: {has_csp}, HSTS: {has_hsts}\n"
        f" [⌬] <b>𝐏𝐚𝐲𝐦e𝐧𝐭 𝐆𝐚𝐭e𝐰𝐚𝐲𝐬</b> ➔ <code>{gateways}</code>\n"
        f" [⌬] <b>𝐂𝐚𝐩𝐭𝐜𝐡𝐚</b> ➔ {captcha}\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f" [⌬] <b>𝐂𝐥𝐨𝐮𝐝𝐟𝐥𝐚𝐫e</b> ➔ {cloudflare}\n"
        f" [⌬] <b>𝐒e𝐜𝐮𝐫𝐢𝐭𝐲</b> ➔ {security_3d}\n"
        f" [⌬] <b>𝐂𝐡e𝐜𝐤out 𝐅𝐢e𝐥𝐝𝐬</b> ➔ {campos_str}\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f" [⌬] <b>𝐒𝐭𝐚𝐭𝐮𝐬</b> ➔ {status}\n"
        f" [⌬] <b>𝐏𝐚𝐠e 𝐒𝐢𝐳e</b> ➔ {tamano_kb} KB\n"
        f" [⌬] <b>𝐑e𝐬𝐩b𝐨𝐧𝐬e 𝐓𝐢𝐦e</b> ➔ {tiempo_respuesta} sec"
    )
    return mensaje

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("👋 Envíame un enlace y te daré un informe de la pasarela de pago.")

async def procesar_mensaje(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url_usuario = update.message.text.strip()
    if not ("." in url_usuario) or " " in url_usuario:
        await update.message.reply_text("❌ Envía un dominio válido (ej: google.com).")
        return
    mensaje_espera = await update.message.reply_text("🔍 Verificando pasarelas de pago...")
    resultado = await analizar_sitio_pro(url_usuario)
    await mensaje_espera.edit_text(resultado, parse_mode="HTML")

# --- SERVIDOR WEB AUXILIAR PARA RENDER ---
class HealthCheckHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Bot activo")
    def log_message(self, format, *args):
        return

def iniciar_servidor_web():
    puerto = int(os.environ.get("PORT", 8080))
    server = HTTPServer(("0.0.0.0", puerto), HealthCheckHandler)
    server.serve_forever()

def main():
    TOKEN = "8904800169:AAE-8y1KJpv3KWqSKDVBCtWNtKIee70SjxI"
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, procesar_mensaje))
    
    print("🤖 Iniciando servidor web de soporte...")
    threading.Thread(target=iniciar_servidor_web, daemon=True).start()
    
    print("🤖 Bot definitivo iniciado con éxito...")
    app.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    main()
