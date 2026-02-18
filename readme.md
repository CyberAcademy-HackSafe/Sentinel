<h1 align="center">
  <br>
  <a href="https://github.com/CyberAcademy-HackSafe/Sentinel"><img src="https://i.ibb.co/dJWXkSh5/IMG-20260217-WA0182.jpg" alt="Sentinel"></a>
  <br>
  Sentinel v1.0
  <br>
</h1>

<h4 align="center">🛡️ CyberAcademy Offensive Security Recon & Automated Audit Tool for Kali Linux</h4>
</p>

<b>Sentinel v1.0</b> es una herramienta de auditoría ofensiva automatizada desarrollado por <b>CyberAcademy – HackSafe</b> que integra:

- Reconocimiento de infraestructura con Nmap (TCP/UDP/OS Detection)  
- Fingerprinting de servicios y versiones  
- Correlación automática con <b>Searchsploit (Top 11 exploits)</b>  
- Detección de WAF y stack tecnológico  
- Auditoría profesional de cabeceras HTTP de seguridad  
- Validación de certificados SSL/TLS  
- Fuzzing agresivo de archivos sensibles  
- Descubrimiento de subdominios comunes  
- Generación automática de <b>reporte HTML profesional</b>  
- Plan de remediación automático  

Diseñado para pentesters, bug bounty hunters y estudiantes de ciberseguridad.

-------------------------------------

<h3>🛡️ Features</h3>

<ul>
<li>Escaneo de red TCP/UDP con Nmap (-sS -sU -A -T4)</li>
<li>Detección de sistema operativo (OS Fingerprinting)</li>
<li>Identificación de servicios y versiones</li>
<li>Correlación automática con Searchsploit (Top 11 por servicio)</li>
<li>Detección de WAF (Cloudflare, Akamai, AWS WAF, Sucuri, ModSecurity, F5)</li>
<li>Identificación de CMS (WordPress, Joomla)</li>
<li>Fingerprint de Web Server y X-Powered-By</li>
<li>Auditoría de cabeceras de seguridad:</li>
<ul>
<li>Content-Security-Policy</li>
<li>X-Frame-Options</li>
<li>Strict-Transport-Security</li>
<li>X-Content-Type-Options</li>
<li>Referrer-Policy</li>
</ul>
<li>Validación de certificado SSL/TLS (fecha de expiración)</li>
<li>Fuzzing de archivos críticos (.env, .git, backups, wp-config, ssh keys)</li>
<li>Descubrimiento de subdominios comunes (dev, api, admin, vpn, mail)</li>
<li>Reporte HTML profesional estilo CyberAcademy</li>
<li>Plan de remediación automático basado en hallazgos</li>
<li>Soporte para dominios e IP</li>
<li>Uso de multithreading + async para máximo rendimiento</li>
</ul>

-------------------------------------

<h3>🛡️ Flujo de Auditoría</h3>

<ol>
<li>Resolución de IP real del objetivo</li>
<li>Escaneo de puertos TCP/UDP con detección de OS</li>
<li>Fingerprint de servicios y correlación con Searchsploit</li>
<li>Auditoría web (WAF, CMS, stack, SSL, headers)</li>
<li>Fuzzing agresivo de archivos sensibles</li>
<li>Enumeración de subdominios comunes</li>
<li>Generación de reporte HTML profesional</li>
<li>Plan de remediación automático</li>
</ol>

-------------------------------------

<h3>🛡️ Instalación</h3>

<pre><code>apt update && apt upgrade -y
git clone https://github.com/CyberAcademy-HackSafe/Sentinel
cd Sentinel
chmod +x install.sh
sudo ./install.sh</code></pre>

-------------------------------------

<h3>🛡️ Uso</h3>

Escaneo de dominio:

<pre><code>sudo sentinel.py example.com</code></pre>

Escaneo de dirección IP:

<pre><code>sudo sentinel.py &lt;IP&gt;</code></pre>

-------------------------------------

<h3>🛡️ Módulos Integrados</h3>

<ul>
<li><b>Infraestructura:</b> Nmap TCP/UDP + OS Detection</li>
<li><b>Exploit Intelligence:</b> Integración con Searchsploit (JSON parsing)</li>
<li><b>Web Security Audit:</b> WAF, CMS, Headers, SSL/TLS</li>
<li><b>Aggressive Fuzzing:</b> Archivos críticos y rutas sensibles</li>
<li><b>Subdomain Discovery:</b> Enumeración de subdominios comunes</li>
<li><b>Professional Reporting:</b> HTML CyberAcademy</li>
</ul>

-------------------------------------

<h3>🛡️ Reporte</h3>

El reporte generado incluye:

<ul>
<li>Resumen de infraestructura (IP, WAF, OS, SSL)</li>
<li>Stack tecnológico detectado</li>
<li>Puertos abiertos y servicios</li>
<li>Top 11 vulnerabilidades correlacionadas (Searchsploit)</li>
<li>Archivos sensibles expuestos</li>
<li>Auditoría de cabeceras HTTP</li>
<li>Plan de remediación profesional</li>
</ul>

Archivo generado automáticamente:

<pre><code>cyberacademy-report_target.html</code></pre>

-------------------------------------

<h3>🛡️ Requisitos</h3>

<ul>
<li>Kali Linux</li>
<li>Python 3</li>
<li>Nmap</li>
<li>Searchsploit</li>
<li>Permisos root</li>
</ul>

-------------------------------------

<h3>⚠️ Warning</h3>

Esta herramienta es únicamente para <b>auditorías autorizadas y fines educativos</b>, el uso no autorizado contra objetivos sin permiso es ilegal y <b>CyberAcademy no se hace responsable del mal uso que se le de a la herramienta</b>

-------------------------------------

<h3>🛡️ Derechos</h3>

Todos los derechos reservados a <b>CyberAcademy – HackSafe</b>

📢 Canal oficial de WhatsApp:<br>
https://whatsapp.com/channel/0029Vb6uWv2HVvTcSS1dsh0O

Enlace de descarga de nuestra aplicación para Android<br>
https://www.mediafire.com/file/nldgho9n4hp83bt/HackSafe.apk/file

Cuenta de TikTok<br>
https://tiktok.com/@cyberacademy.hsafe

-------------------------------------

<h3>Únete y aprende</h3>

Descarga nuestra aplicación oficial para android desde este repositorio o enlace de mediafire, registrate y aprende <b>contamos con plan premium y gratuito</b>, cada semana subimos nuevos cursos.

<h3>⚠️ IMPORTANTE ⚠️</h3>

<b>Antes de realizar algun pagó del plan premium/cursos/servicios, verifica antes desde el canal de WhatsApp, Cuenta de tiktok y aplicación oficial</b>, ya que se han estado pasando por nosotros con intenciones de estafar, no te dejes estafar y contactanos por el medio de contacto oficial.
