import os
import json
import sqlite3
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, Response

# --- CONFIGURACIÓN DINÁMICA DEL SERVIDOR (DevSecOps) ---
# Lee las variables del sistema operativo inyectadas por Docker.
# Si alguien lo ejecuta sin Docker, usa los valores por defecto (segundo parámetro).
AUTH_USER = os.environ.get("WIDS_USER", "admin")
AUTH_PASS = os.environ.get("WIDS_PASS", "wids_tfm_2026")
PUERTO_SERVIDOR = int(os.environ.get("WIDS_PORT", 5000))

# Rutas dinámicas para permitir volúmenes separados (/config y /data)
ARCHIVO_CONFIG = os.environ.get("WIDS_CONFIG_PATH", "wids_config.json")
ARCHIVO_LOG_SIEM = os.environ.get("WIDS_LOG_PATH", "alertas_wids.json")
DB_NAME = os.environ.get("WIDS_DB_PATH", "wids_central.db")

app = Flask(__name__)

# --- LÓGICA DE AUTENTICACIÓN BASIC AUTH ---
def verificar_auth(username, password):
    return username == AUTH_USER and password == AUTH_PASS

def acceso_denegado():
    return Response(
        'Acceso denegado: Credenciales inválidas.\n', 401,
        {'WWW-Authenticate': 'Basic realm="Acceso Restringido WIDS"'}
    )

def requiere_auth(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        auth = request.authorization
        if not auth or not verificar_auth(auth.username, auth.password):
            print(f"[!] Intento de conexión bloqueado (Credenciales inválidas) desde {request.remote_addr}")
            return acceso_denegado()
        return f(*args, **kwargs)
    return decorador

# --- CLASE PRINCIPAL ---
class ServidorWIDS:
    def __init__(self):
        self.inicializar_db()
        self.alertas_enviadas_sesion = set()

    def inicializar_db(self):
        conexion = sqlite3.connect(DB_NAME)
        cursor = conexion.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS telemetria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                bssid TEXT,
                ssid TEXT,
                canal INTEGER,
                vht BOOLEAN,
                fingerprint_sha256 TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alertas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                modulo TEXT,
                accion TEXT,
                severidad INTEGER,
                mensaje TEXT,
                json_raw TEXT
            )
        ''')
        conexion.commit()
        conexion.close()

    def guardar_alerta(self, alerta):
        with open(ARCHIVO_LOG_SIEM, "a") as f:
            f.write(json.dumps(alerta) + "\n")
            
        conexion = sqlite3.connect(DB_NAME)
        cursor = conexion.cursor()
        cursor.execute(
            "INSERT INTO alertas (modulo, accion, severidad, mensaje, json_raw) VALUES (?, ?, ?, ?, ?)",
            (alerta.get("event", {}).get("module", "wids"), alerta.get("event", {}).get("action", "unknown"),
             alerta.get("event", {}).get("severity", 0), alerta.get("message", ""), json.dumps(alerta))
        )
        conexion.commit()
        conexion.close()

    def guardar_telemetria(self, datos):
        conexion = sqlite3.connect(DB_NAME)
        cursor = conexion.cursor()
        cursor.execute(
            "INSERT INTO telemetria (bssid, ssid, canal, vht, fingerprint_sha256) VALUES (?, ?, ?, ?, ?)",
            (datos.get("bssid"), datos.get("ssid"), datos.get("canal"), datos.get("vht"), datos.get("fingerprint"))
        )
        conexion.commit()
        conexion.close()

    def evaluar_whitelisting(self, datos):
        try:
            with open(ARCHIVO_CONFIG, "r") as f:
                config = json.load(f)
        except Exception:
            print(f"[!] Error leyendo {ARCHIVO_CONFIG}. Se aborta la evaluación.")
            return

        bssid = datos.get("bssid")
        ssid = datos.get("ssid")
        fingerprint_recibido = datos.get("fingerprint")
        ssid_protegido = config.get("general", {}).get("ssid_corporativo", "")
        lista_blanca = config.get("fingerprints_autorizados", {})

        if bssid in lista_blanca:
            if fingerprint_recibido != lista_blanca[bssid]:
                id_alerta = f"eviltwin_{bssid}"
                if id_alerta not in self.alertas_enviadas_sesion:
                    alerta = {
                        "@timestamp": datetime.utcnow().isoformat() + "Z",
                        "agent": {"name": datos.get("agente", "AGENTE_DESCONOCIDO")},
                        "event": {"module": "wids", "action": "hardware_downgrade", "severity": 9},
                        "wifi": {"bssid": bssid, "ssid": ssid},
                        "message": f"CRITICO: El BSSID {bssid} ha mutado su hardware. Posible Evil Twin. Fingerprint anómalo: {fingerprint_recibido}"
                    }
                    self.guardar_alerta(alerta)
                    print(f"\n[!] ALERTA INTERNA GENERADA: Evil Twin detectado en {bssid}")
                    self.alertas_enviadas_sesion.add(id_alerta)
                    
        elif bssid not in lista_blanca and ssid == ssid_protegido:
            id_alerta = f"rogue_{bssid}"
            if id_alerta not in self.alertas_enviadas_sesion:
                alerta = {
                    "@timestamp": datetime.utcnow().isoformat() + "Z",
                    "agent": {"name": datos.get("agente", "AGENTE_DESCONOCIDO")},
                    "event": {"module": "wids", "action": "rogue_ap_detected", "severity": 8},
                    "wifi": {"bssid": bssid, "ssid": ssid},
                    "message": f"ALERTA: Nuevo Rogue AP detectado emitiendo el SSID '{ssid}'"
                }
                self.guardar_alerta(alerta)
                print(f"\n[!] ALERTA INTERNA GENERADA: Rogue AP detectado ({bssid})")
                self.alertas_enviadas_sesion.add(id_alerta)

servidor = ServidorWIDS()

# --- ENDPOINTS PROTEGIDOS ---
@app.route('/api/config', methods=['GET'])
@requiere_auth
def obtener_configuracion():
    try:
        with open(ARCHIVO_CONFIG, "r") as f:
            return jsonify(json.load(f)), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/telemetria', methods=['POST'])
@requiere_auth
def recibir_telemetria():
    datos = request.json
    servidor.guardar_telemetria(datos)
    servidor.evaluar_whitelisting(datos)
    return jsonify({"status": "ok"}), 201

@app.route('/api/alerta', methods=['POST'])
@requiere_auth
def recibir_alerta():
    alerta = request.json
    servidor.guardar_alerta(alerta)
    print(f"[*] ¡Alerta DoS recibida desde agente!: {alerta.get('message')}")
    return jsonify({"status": "ok"}), 201

if __name__ == '__main__':
    print("="*50)
    print(f"SERVIDOR CENTRAL SECURE-WIDS (PUERTO {PUERTO_SERVIDOR})")
    print("="*50)
    app.run(host='0.0.0.0', port=PUERTO_SERVIDOR, debug=False)
