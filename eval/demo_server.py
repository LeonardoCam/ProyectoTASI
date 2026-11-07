"""Servidor de demostración con web simulada (para capturas y exposición sin red). Uso: python -m eval.demo_server"""
import uvicorn
from app import api
from eval.sim import World

w = World(); w.delay = False
w.add_chain(["https://bit.ly/promo-yape", "https://go.trk-mail-cdn.com/r/8f2k", "http://yape-verifica-x3k.xyz/login"])
w.ages["yape-verifica-x3k.xyz"] = 4
w.add_chain(["https://t.co/aulaVirtual", "https://www.upch.edu.pe/"]); w.ages["upch.edu.pe"] = 7200
w.add_chain(["https://cutt.ly/nubeapp", "https://l.campana-mail.com/x/91", "http://www.nubeab12.com/inicio"]); w.ages["nubeab12.com"] = 45
w.add_chain(["https://tinyurl.com/factura-sunat", "https://redir.sunat-cobranza.top/a", "http://sunat-cobranza.top/pago/clave"]); w.ages["sunat-cobranza.top"] = 11
w.install()
api.limiter.per_minute = 0
uvicorn.run(api.app, host="127.0.0.1", port=8000, log_level="warning")
