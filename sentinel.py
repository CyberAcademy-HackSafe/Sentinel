#!/usr/bin/env python3
import sys
import asyncio
import aiohttp
import nmap
import subprocess
import json
import socket
import threading
import warnings
import requests
import re
import ssl
import urllib3
from datetime import datetime
from tqdm import tqdm

# Configuraciones iniciales
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

class SentinelEliteV17:
    def __init__(self, target):
        # Normalización de la URL y Host
        self.target_url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        self.host = self.target_url.replace("http://", "").replace("https://", "").split('/')[0]
        self.report_name = f"cyberacademy-report_{self.host}.html"
        self.lock = threading.Lock()
        
        # Estructura masiva de datos
        self.data = {
            "os": "No detectado",
            "waf": "No detectado",
            "real_ip": "Detectando...",
            "ssl_info": "N/A",
            "tech": [],
            "headers": [],
            "ports": [],
            "exploits": [],
            "subs": [],
            "sensitive_files": [],
            "remedies": set(),
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    def log(self, key, value):
        with self.lock:
            if isinstance(self.data[key], list):
                if value not in self.data[key]: self.data[key].append(value)
            else: self.data[key] = value

    # --- 1. INFRAESTRUCTURA: NMAP (TCP/UDP/OS) ---
    def network_recon(self):
        try:
            self.log("real_ip", socket.gethostbyname(self.host))
            nm = nmap.PortScanner()
            # Escaneo agresivo: -A (OS/Version/Scripts), -sU (UDP), -T4 (Velocidad)
            # Escaneamos puertos críticos de ambos protocolos
            args = "-sS -sU -A --osscan-guess -T4"
            nm.scan(self.host, "21,22,53,80,161,443,3306,3389,8080", arguments=args)
            
            if self.host in nm.all_hosts():
                # Detección de OS
                os_match = nm[self.host].get('osmatch', [])
                self.log("os", os_match[0]['name'] if os_match else "Firewall Activo / OS Desconocido")
                
                for proto in nm[self.host].all_protocols():
                    for port in nm[self.host][proto]:
                        svc = nm[self.host][proto][port]
                        p_info = {
                            "port": f"{port}/{proto.upper()}",
                            "service": svc['name'],
                            "prod": svc['product'],
                            "ver": svc['version']
                        }
                        self.log("ports", p_info)
                        
                        # Si hay producto, buscar tecnología y exploits
                        if svc['product']:
                            self.log("tech", {"name": f"Servicio {port}", "val": f"{svc['product']} {svc['version']}"})
                            self._fetch_searchsploit(svc['product'], svc['version'])
        except Exception as e:
            print(f"[-] Error en Escaneo de Red: {e}")

    # --- 2. BÚSQUEDA DE EXPLOITS (TOP 11) ---
    def _fetch_searchsploit(self, prod, ver):
        clean_prod = re.sub(r'(?i)httpd|server', '', prod).strip()
        query = f"{clean_prod} {ver}".strip()
        try:
            res = subprocess.run(["searchsploit", query, "--json"], capture_output=True, text=True)
            if res.stdout:
                results = json.loads(res.stdout).get('RESULTS_EXPLOIT', [])
                for e in results[:11]:
                    self.log("exploits", {
                        "service": f"{prod} {ver}",
                        "title": e['Title'],
                        "link": f"https://www.exploit-db.com/exploits/{e['EDB-ID']}"
                    })
        except: pass

    # --- 3. AUDITORÍA WEB: WAF, CMS, LENGUAJES Y CABECERAS ---
    def web_audit(self):
        try:
            # SSL Check si es 443
            if "https" in self.target_url or ":443" in self.target_url:
                try:
                    ctx = ssl.create_default_context()
                    with socket.create_connection((self.host, 443), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                            cert = ssock.getpeercert()
                            self.log("ssl_info", f"Expira: {cert['notAfter']}")
                except: self.log("ssl_info", "Error en Certificado / Auto-firmado")

            # Request Principal
            r = requests.get(self.target_url, timeout=10, verify=False, headers={'User-Agent': 'CyberAcademy-Security-Bot/V17'})
            h = r.headers
            body = r.text.lower()

            # A. Detección de WAF
            waf_db = {
                "Cloudflare": "cf-ray", "Akamai": "akamai", "Sucuri": "x-sucuri", 
                "AWS WAF": "awselb", "ModSecurity": "mod_security", "F5 Big-IP": "f5"
            }
            for name, sig in waf_db.items():
                if sig in str(h).lower(): self.log("waf", name)

            # B. CMS & Stack Tecnológico
            if "wp-content" in body: self.log("tech", {"name": "CMS", "val": "WordPress"})
            if "joomla" in body: self.log("tech", {"name": "CMS", "val": "Joomla"})
            
            server_head = h.get('Server', '')
            if server_head: self.log("tech", {"name": "Web Server", "val": server_head})
            
            powered_by = h.get('X-Powered-By', '')
            if powered_by: self.log("tech", {"name": "Lenguaje/Stack", "val": powered_by})

            # C. Auditoría de Cabeceras Pro
            sec_headers = {
                "Content-Security-Policy": {"risk": "XSS/Injection", "tip": "Definir política CSP."},
                "X-Frame-Options": {"risk": "Clickjacking", "tip": "Usar DENY o SAMEORIGIN."},
                "Strict-Transport-Security": {"risk": "MITM/SSL Strip", "tip": "Habilitar HSTS."},
                "X-Content-Type-Options": {"risk": "MIME Sniffing", "tip": "Usar nosniff."},
                "Referrer-Policy": {"risk": "Info Leakage", "tip": "Configurar strict-origin."}
            }
            for hc, info in sec_headers.items():
                found = any(hc.lower() == k.lower() for k in h.keys())
                status = "✅ PRESENTE" if found else "❌ AUSENTE"
                self.log("headers", {"name": hc, "status": status, "risk": info['risk']})
                if not found:
                    self.data["remedies"].add(f"Seguridad Web: Implementar cabecera {hc} para mitigar {info['risk']}.")

        except Exception as e:
            print(f"[-] Error Web Audit: {e}")

    # --- 4. FUZZING AGRESIVO (RUTAS Y ARCHIVOS) ---
    async def aggressive_fuzzing(self):
        critical_paths = [
            '/.env', '/.git/config', '/server-status', '/phpinfo.php', '/robots.txt',
            '/.htaccess', '/config.php.bak', '/backup.sql', '/.ssh/id_rsa', '/admin/',
            '/wp-config.php', '/.vscode/settings.json', '/.npmrc', '/package.json'
        ]
        async with aiohttp.ClientSession() as session:
            tasks = [self._check_path(self.target_url + p, session) for p in critical_paths]
            # Subdominios comunes
            subs = ['www', 'dev', 'api', 'admin', 'test', 'mail', 'vpn']
            for s in subs:
                tasks.append(self._check_sub(f"http://{s}.{self.host}", session))
            await asyncio.gather(*tasks)

    async def _check_path(self, url, session):
        try:
            async with session.get(url, timeout=4, allow_redirects=False) as r:
                if r.status == 200:
                    self.log("sensitive_files", url)
                    self.data["remedies"].add(f"CRÍTICO: Archivo sensible expuesto en {url}. Restringir acceso.")
        except: pass

    async def _check_sub(self, domain, session):
        try:
            async with session.get(domain, timeout=3) as r:
                if r.status < 400: self.log("subs", domain)
        except: pass

    # --- 5. GENERACIÓN DEL REPORTE CYBERACADEMY ---
    def generate_report(self):
        html = f"""
        <html><head><title>CyberAcademy Audit: {self.host}</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 30px; line-height: 1.6; }}
            .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 25px; margin-bottom: 30px; }}
            h1 {{ color: #58a6ff; text-align: center; font-size: 2.5em; border-bottom: 2px solid #58a6ff; }}
            h2 {{ color: #79c0ff; border-left: 4px solid #58a6ff; padding-left: 10px; margin-top: 0; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            th, td {{ padding: 12px; border: 1px solid #30363d; text-align: left; }}
            th {{ background: #21262d; color: #58a6ff; }}
            .danger {{ color: #ff7b72; font-weight: bold; }}
            .success {{ color: #3fb950; }}
            .tag {{ background: #388bfd; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; margin-right: 5px; }}
            .remedy-item {{ background: #232113; border-left: 4px solid #d29922; padding: 10px; margin-top: 10px; border-radius: 4px; }}
        </style></head><body>
            <h1>🎓 CYBERACADEMY SECURITY REPORT</h1>
            <p style="text-align:center;"><b>Fecha del Escaneo:</b> {self.data['scan_time']} | <b>Objetivo:</b> {self.host}</p>

            <div class="card">
                <h2>[+] Resumen de Infraestructura</h2>
                <p><b>Dirección IP:</b> {self.data['real_ip']} | <b>WAF Detectado:</b> {self.data['waf']}</p>
                <p><b>Sistema Operativo:</b> <span class="tag">{self.data['os']}</span></p>
                <p><b>SSL/TLS Status:</b> {self.data['ssl_info']}</p>
                <p><b>Stack Tecnológico:</b> {' '.join(f"<span class='tag'>{t['name']}: {t['val']}</span>" for t in self.data['tech'])}</p>
            </div>

            <div class="card">
                <h2>[!] Hallazgos Críticos (Fuzzing)</h2>
                {''.join(f"<p class='danger'>⚠️ URL EXPUESTA: <a href='{f}' style='color:#ff7b72;'>{f}</a></p>" for f in self.data['sensitive_files']) if self.data['sensitive_files'] else "<p class='success'>No se detectaron archivos sensibles expuestos.</p>"}
            </div>

            <div class="card">
                <h2>[!] Análisis de Vulnerabilidades (Top 11 Searchsploit)</h2>
                <table><tr><th>Servicio Detectado</th><th>Vulnerabilidad Identificada</th><th>Exploit-DB</th></tr>
                {''.join(f"<tr><td>{e['service']}</td><td class='danger'>{e['title']}</td><td><a href='{e['link']}' target='_blank' style='color:#58a6ff;'>[VER EXPLOIT]</a></td></tr>" for e in self.data['exploits'])}
                </table>
            </div>

            <div class="card">
                <h2>[?] Auditoría de Cabeceras HTTP</h2>
                <table><tr><th>Cabecera</th><th>Estado</th><th>Riesgo Asociado</th></tr>
                {''.join(f"<tr><td>{h['name']}</td><td class='{'success' if '✅' in h['status'] else 'danger'}'>{h['status']}</td><td>{h['risk']}</td></tr>" for h in self.data['headers'])}
                </table>
            </div>

            <div class="card">
                <h2>[*] Análisis de Puertos y Servicios (TCP/UDP)</h2>
                <table><tr><th>Puerto/Proto</th><th>Servicio</th><th>Versión Detectada</th></tr>
                {''.join(f"<tr><td>{p['port']}</td><td>{p['service']}</td><td>{p['prod']} {p['ver']}</td></tr>" for p in self.data['ports'])}
                </table>
            </div>

            <div class="card">
                <h2>[✓] Plan de Remediación Profesional</h2>
                {''.join(f"<div class='remedy-item'>• {r}</div>" for r in self.data['remedies'])}
            </div>
        </body></html>
        """
        with open(self.report_name, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"\n[💎] Auditoría Finalizada con Éxito. Reporte guardado como: {self.report_name}")

# --- PUNTO DE ENTRADA ---
async def main():
    if len(sys.argv) < 2:
        print("Uso: sudo python3 sentinel.py <ip o dominio.com>")
        return
    
    scanner = SentinelEliteV17(sys.argv[1])
    print(f"[*] Iniciando CyberAcademy Audit sobre: {scanner.host}")

    with tqdm(total=4, desc="Progreso de Auditoría") as pbar:
        # Fase 1: Infraestructura (Thread)
        t_infra = threading.Thread(target=scanner.network_recon)
        t_infra.start()
        
        # Fase 2: Web Audit
        scanner.web_audit()
        pbar.update(1)
        
        # Fase 3: Aggressive Fuzzing
        await scanner.aggressive_fuzzing()
        pbar.update(1)
        
        # Sincronización
        t_infra.join()
        pbar.update(1)
        
        # Fase 4: Reporte Final
        scanner.generate_report()
        pbar.update(1)

if __name__ == "__main__":
    asyncio.run(main())
