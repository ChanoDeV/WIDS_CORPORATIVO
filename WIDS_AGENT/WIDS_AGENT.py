import argparse
import hashlib
import json
import subprocess
import threading
import time
import requests
from datetime import datetime
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt

class AgenteWIDS:
    def __init__(self, interfaz=None, archivo_pcap=None, url_servidor="http://127.0.0.1:5000", usuario="admin", password="password", canales="1,6,11"):
        self.interfaz = interfaz
        self.archivo_pcap = archivo_pcap
        self.ssid_corporativo = ""
        self.url_servidor = url_servidor.rstrip('/')
        self.auth_creds = (usuario, password)
        self.umbral_dos_pps = 1000
        self.aps_descubiertos_sesion = set()
        self.paquetes_segundo_actual = 0
        self.tiempo_ventana = None
        self.canales_hopper = [int(c.strip()) for c in canales.split(",")]
        self.hopper_activo = False
        self.hilo_hopper = None

    def solicitar_configuracion(self):
        print(f"[*] Esperando al Servidor Central en {self.url_servidor}...")
        while True:
            try:
                respuesta = requests.get(f"{self.url_servidor}/api/config", auth=self.auth_creds, timeout=5)
                respuesta.raise_for_status()
                config = respuesta.json()
                self.ssid_corporativo = config["general"]["ssid_corporativo"]
                self.umbral_dos_pps = config["general"]["umbral_dos_pps"]
                print(f"[+] Configuración recibida. Protegiendo SSID: '{self.ssid_corporativo}' (Umbral: {self.umbral_dos_pps} pps)")
                return True
            except requests.exceptions.RequestException:
                time.sleep(5)

    def enviar_alerta(self, alerta):
        try:
            requests.post(f"{self.url_servidor}/api/alerta", json=alerta, auth=self.auth_creds, timeout=2)
        except: pass 

    def enviar_telemetria(self, datos_ap):
        try:
            requests.post(f"{self.url_servidor}/api/telemetria", json=datos_ap, auth=self.auth_creds, timeout=2)
        except: pass

    def generar_fingerprint(self, bssid, ssid, canal, vht):
        cadena_base = f"{bssid}_{ssid}_{canal}_{vht}"
        return hashlib.sha256(cadena_base.encode('utf-8')).hexdigest()

    def habilitar_modo_monitor(self):
        print(f"[*] Esperando a que el hardware '{self.interfaz}' esté disponible en el sistema...")
        while True:
            comprobacion = subprocess.run(["ip", "link", "show", self.interfaz], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if comprobacion.returncode == 0:
                print(f"[*] Interfaz '{self.interfaz}' detectada. Configurando Modo Monitor...")
                try:
                    subprocess.run(["ip", "link", "set", self.interfaz, "down"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["iw", "dev", self.interfaz, "set", "type", "monitor"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["ip", "link", "set", self.interfaz, "up"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    print(f"[+] ¡Éxito! Interfaz acorazada y lista para la escucha.")
                    return True
                except subprocess.CalledProcessError:
                    print(f"[!] La interfaz existe, pero está bloqueada (posible rfkill). Reintentando...")
            time.sleep(5)

    def motor_salto_canal(self):
        print(f"[*] Hilo Hopper iniciado. Saltando entre canales: {self.canales_hopper}")
        indice = 0
        while self.hopper_activo:
            canal_actual = self.canales_hopper[indice % len(self.canales_hopper)]
            try:
                subprocess.run(["iw", "dev", self.interfaz, "set", "channel", str(canal_actual)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError: pass
            indice += 1
            time.sleep(0.5)

    def analizar_dos_volumetrico(self, pkt):
        if not (pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 12):
            return
        tiempo_paquete = int(float(pkt.time))
        if self.tiempo_ventana is None:
            self.tiempo_ventana = tiempo_paquete

        if tiempo_paquete == self.tiempo_ventana:
            self.paquetes_segundo_actual += 1
            if self.paquetes_segundo_actual == self.umbral_dos_pps + 1:
                mac_sospechosa = pkt[Dot11].addr2 if pkt.haslayer(Dot11) and pkt[Dot11].addr2 else "Desconocida"
                alerta = {
                    "@timestamp": datetime.utcnow().isoformat() + "Z",
                    "event": {"module": "wids", "action": "volumetric_dos_detected", "severity": 10},
                    "source": {"mac": mac_sospechosa},
                    "message": f"CRITICO: Pico anómalo de tráfico (> {self.umbral_dos_pps} tramas/segundo)."
                }
                print(f"[!] ALERTA LOCAL: Ataque DoS detectado desde {mac_sospechosa}")
                self.enviar_alerta(alerta)
        else:
            self.tiempo_ventana = tiempo_paquete
            self.paquetes_segundo_actual = 1

    def analizar_infraestructura_ap(self, pkt):
        if pkt.haslayer(Dot11Beacon) and pkt.haslayer(Dot11Elt):
            bssid = pkt[Dot11].addr3
            ssid = "<Oculto>"
            canal = 0
            soporta_vht = False
            try:
                capa_actual = pkt[Dot11Elt]
                while isinstance(capa_actual, Dot11Elt):
                    if capa_actual.ID == 0:
                        try: ssid = capa_actual.info.decode('utf-8', errors='ignore')
                        except: pass
                    elif capa_actual.ID == 3:
                        try: canal = int.from_bytes(capa_actual.info, byteorder='little')
                        except: pass
                    elif capa_actual.ID == 191:
                        soporta_vht = True
                    capa_actual = capa_actual.payload
            except Exception:
                pass

            if ssid and ssid != "<Oculto>":
                if bssid not in self.aps_descubiertos_sesion:
                    self.aps_descubiertos_sesion.add(bssid)
                    fingerprint = self.generar_fingerprint(bssid, ssid, canal, soporta_vht)
                    datos_telemetria = {
                        "bssid": bssid, "ssid": ssid, "canal": canal, 
                        "vht": soporta_vht, "fingerprint": fingerprint
                    }
                    print(f"[*] Nuevo AP interceptado: SSID '{ssid}' con MAC {bssid}. Enviando a la API...")
                    self.enviar_telemetria(datos_telemetria)

    def procesar_paquete(self, pkt):
        if not pkt.haslayer(Dot11): return
        self.analizar_dos_volumetrico(pkt)
        self.analizar_infraestructura_ap(pkt)

    def ejecutar(self):
        if not self.solicitar_configuracion(): return
        try:
            if self.archivo_pcap:
                print(f"[*] Leyendo archivo Offline: {self.archivo_pcap}")
                sniff(offline=self.archivo_pcap, prn=self.procesar_paquete, store=0)
            elif self.interfaz:
                if self.habilitar_modo_monitor():
                    self.hopper_activo = True
                    self.hilo_hopper = threading.Thread(target=self.motor_salto_canal, daemon=True)
                    self.hilo_hopper.start()
                    print(f"[*] Hilo principal escuchando interfaz en vivo: {self.interfaz}")
                    sniff(iface=self.interfaz, prn=self.procesar_paquete, store=0)
        except KeyboardInterrupt:
            print("\n[*] Interrupción del usuario. Apagando...")
        except Exception as e:
            print(f"\n[!] Error crítico: {e}")
        finally:
            self.hopper_activo = False
            if self.hilo_hopper: self.hilo_hopper.join(timeout=1)
            print("[*] Análisis del Agente finalizado.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agente Remoto WIDS (V4.7)")
    grupo = parser.add_mutually_exclusive_group(required=True)
    grupo.add_argument("-f", "--file", help="Ruta pcap.")
    grupo.add_argument("-i", "--interface", help="Interfaz (ej. wlan0).")
    parser.add_argument("-s", "--server", default="http://127.0.0.1:5000")
    parser.add_argument("-u", "--user", default="admin")
    parser.add_argument("-p", "--password", default="wids_tfm_2026")
    parser.add_argument("-c", "--channels", default="1,6,11")
    args = parser.parse_args()
    
    print("="*50)
    print("AGENTE DISTRIBUIDO WIDS V4.7 (Automatizado)")
    print("="*50)
    agente = AgenteWIDS(interfaz=args.interface, archivo_pcap=args.file, url_servidor=args.server, usuario=args.user, password=args.password, canales=args.channels)
    agente.ejecutar()
