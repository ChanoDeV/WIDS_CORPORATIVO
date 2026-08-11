import hashlib
import json
import os

def main():
    print("==================================================")
    print(" GENERADOR COMPLETO DE CONFIGURACIÓN WIDS")
    print("==================================================")
    
    # 1. Pedimos los datos globales de la empresa una sola vez
    ssid_corporativo = input("Introduce el SSID corporativo a proteger (ej. wifi-old): ").strip()
    
    try:
        umbral_dos = int(input("Introduce el umbral DoS en Paquetes Por Segundo (ej. 100): ").strip())
    except ValueError:
        umbral_dos = 100
        print("[*] Valor no válido. Configurando 100 pps por defecto.")

    hashes_generados = {}
    
    # 2. Bucle para registrar todas las antenas/APs de la organización
    while True:
        print("\n--- Registro de Punto de Acceso Legítimo ---")
        bssid = input("Introduce la MAC del AP (ej. f0:9f:c2:71:22:11): ").lower().strip()
        canal = input("Introduce el Canal de este AP: ").strip()
        
        vht_input = input("¿Soporta Wi-Fi 5 / VHT? (s/n): ").lower().strip()
        vht = "True" if vht_input == 's' else "False"

        # El cálculo del hash utiliza automáticamente el SSID global introducido arriba
        cadena_base = f"{bssid}_{ssid_corporativo}_{canal}_{vht}"
        hash_resultado = hashlib.sha256(cadena_base.encode('utf-8')).hexdigest()
        
        hashes_generados[bssid] = hash_resultado
        print(f"[+] AP mapeado en el inventario.")

        continuar = input("\n¿Deseas añadir otro AP al inventario? (s/n): ").lower().strip()
        if continuar != 's':
            break

    # 3. Construimos la estructura exacta que espera el servidor
    config_final = {
        "general": {
            "ssid_corporativo": ssid_corporativo,
            "umbral_dos_pps": umbral_dos
        },
        "fingerprints_autorizados": hashes_generados
    }

    # 4. Imprimimos el JSON estructurado y LO GUARDAMOS EN LA CARPETA CONFIG
    json_output = json.dumps(config_final, indent=4)
    
    print("\n\n==================================================")
    print(" CONTENIDO COMPLETO GENERADO")
    print("==================================================")
    print(json_output)
    print("==================================================\n")

    # Escribir físicamente en el disco dentro de la carpeta 'config'
    directorio_destino = "config"
    nombre_archivo = os.path.join(directorio_destino, "wids_config.json")
    
    try:
        # Creamos la carpeta 'config' si no existe previamente
        os.makedirs(directorio_destino, exist_ok=True)
        
        with open(nombre_archivo, "w") as f:
            f.write(json_output)
        print(f"[+] ¡Éxito! El archivo se ha guardado correctamente en la ruta: '{nombre_archivo}'")
    except Exception as e:
        print(f"[!] Error crítico al guardar el archivo: {e}")

if __name__ == "__main__":
    main()
