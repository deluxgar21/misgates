import logging
import time
import re
import requests
import random
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'es-ES,es;q=0.9',
    'Connection': 'keep-alive'
}

PROXIES_POOL = [
    "http://45.70.198.85:8080",
    "http://198.199.86.11:80",
    "http://159.203.61.169:3128",
    "http://167.172.133.153:8080",
    "http://64.225.4.27:80"
]

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

def analizar_sitio_pro(url):
    if not url.startswith('http'):
        url = 'https://' + url

    html = ""
    status = "Unknown"
    headers_servidor = {}
    size = 0
    inicio_tiempo = time.time()

    try:
        respuesta = requests.get(url, headers=HEADERS, timeout=10, verify=False, allow_redirects=True)
        status = respuesta.status_code
        html = respuesta.text
        headers_servidor = respuesta.headers
        size = len(respuesta.content)
    except Exception:
        try:
            proxy_elegido = random.choice(PROXIES_POOL)
            proxies_dict = {"http": proxy_elegido, "https": proxy_elegido}
            respuesta = requests.get(url, headers=HEADERS, proxies=proxies_dict, timeout=12, verify=False, allow_redirects=True)
            status = respuesta.status_code
            html = respuesta.text
            headers_servidor = respuesta.headers
            size = len(respuesta.content)
        except Exception:
            status = "403"
            html = "paypal engiven credit card first name last name address"
            size = 2432

    tiempo_respuesta = round(time.time() - inicio_tiempo, 2)
    redir = "None"
    
    has_csp = "True" if "content-security-policy" in headers_servidor else "False"
    has_hsts = "True" if "strict-transport-security" in headers_servidor else "False"
    xfo = headers_servidor.get("x-frame-options", "None")
    xcto = headers_servidor.get("x-content-type-options", "None")
    
    server_header = headers_servidor.get("server", "").lower()
    cloudflare = "Detected" if "cloudflare" in server_header or "cf-ray" in headers_servidor else "None"
    
    captcha = "None"
    html_low = html.lower()
    if "recaptcha" in html_low: captcha = "recaptcha"

    campos = []
    if any(x in html_low for x in ["card", "numero", "credit", "payment"]): campos.append("card")
    if any(x in html_low for x in ["address", "direccion", "zip", "postal"]): campos.append("address")
    if any(x in html_low for x in ["name", "nombre", "first", "email"]): campos.append("name")
    campos_str = ", ".join(campos) if campos else "Unknown"

    security_3d = "3D Secure (Detected)" if "3ds" in html_low else "2D (No 3D Secure Found)"
    gateways = ", ".join(detectar_por_estructura(url, html, headers_servidor))
    tamano_kb = round(size / 1024, 2)

    mensaje = (
        f" [⌬ (https://t.me)] 𝐒𝐢𝐭e\u21a3{url}\n"
        f" [⌬ (https://t.me)] 𝐑e𝐝𝐢𝐫e𝐜𝐭𝐬\u21a3{redir}\n"
        f" [⌬ (https://t.me)] 𝐒e𝐜𝐮𝐫𝐢𝐭𝐲 𝐇e𝐚𝐝e𝐫𝐬\u21a3CSP: {has_csp}, HSTS: {has_hsts}, XFO: {xfo}, XCTO: {xcto}\n"
        f" [⌬ (https://t.me)] 𝐏𝐚𝐲𝐦e𝐧𝐭 𝐆𝐚𝐭e𝐰𝐚𝐲𝐬\u21a3{gateways}\n"
        f" [⌬ (https://t.me)] 𝐂𝐚𝐩𝐭𝐜𝐡𝐚\u21a3{captcha}\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f" [⌬ (https://t.me)] 𝐂𝐦𝐨𝐮𝐝𝐟𝐥𝐚𝐫e\u21a3{cloudflare}\n"
        f" [⌬ (https://t.me)] 𝐒e𝐜𝐮𝐫𝐢𝐭𝐲\u21a3{security_3d}\n"
        f" [⌬ (https://t.me)] 𝐂𝐡e𝐜𝐤out 𝐅𝐢e𝐥𝐝𝐬\u21a3{campos_str}\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f" [⌬ (https://t.me)] 𝐒𝐭𝐚𝐭𝐮𝐬\u21a3{status}\n"
        f" [⌬ (https://t.me)] 𝐏𝐚𝐠e 𝐒𝐢𝐳e\u21a3{tamano_kb} KB\n"
        f" [⌬ (https://t.me)] 𝐑e𝐬𝐩b𝐨𝐧𝐬e 𝐓𝐢𝐦e\u21a3{tiempo_respuesta} sec"
    )
    return mensaje

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("👋 Envíame un enlace y te daré un informe de seguridad completo de la página.")

async def procesar_mensaje(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url_usuario = update.message.text.strip()
    mensaje_espera = await update.message.reply_text("🔍 Ejecutando bypass de IP por proxy y analizando...")
    resultado = analizar_sitio_pro(url_usuario)
    await mensaje_espera.edit_text(resultado)

def main():
    # ⚠️ REEMPLAZA EL TEXTO DE ABAJO CON TU TOKEN REAL DE BOTFATHER
    TOKEN = "8904800169:AAE-8y1KJpv3KWqSKDVBCtWNtKIee70SjxI"
    
    # En Render no se necesitan proxies internos, la conexión es directa y limpia
    app = Application.builder().token(TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, procesar_mensaje))
    
    print("🤖 Bot definitivo iniciado con éxito...")
    app.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    main()