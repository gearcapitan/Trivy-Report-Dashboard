import json
import sys
import os
import html

# --- ESTILOS CSS v7.0: TEMA OSCURO EJECUTIVO ---
HTML_HEADER = """
<style>
    body { 
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; 
        margin: 0;
        padding: 2em;
        background-color: #121212; 
        color: #e0e0e0;
    }
    .container { 
        max-width: 1400px; 
        margin: auto; 
        background-color: #1e1e1e; 
        padding: 20px 40px; 
        border-radius: 12px;
        border: 1px solid #333;
    }
    .report-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 2px solid #007bff;
        padding-bottom: 15px;
    }
    .report-header img {
        /* --- MEJORA: Aumenta el tamaño del logo --- */
        height: 70px;
        max-width: 250px;
    }
    h1, h2, h3 { 
        color: #ffffff; 
        border-bottom: none;
    }
    h3 { 
        margin-top: 40px; 
        border-bottom: 1px dashed #444;
        padding-bottom: 10px;
    }
    table { 
        width: 100%; 
        border-collapse: collapse; 
        margin-top: 20px; 
        table-layout: fixed; 
    }
    th, td { 
        padding: 12px 15px; 
        text-align: left; 
        border-bottom: 1px solid #333;
        word-break: break-word; 
    }
    th { 
        background-color: #2a2a2a; 
        color: #f0f0f0; 
        font-weight: 600;
    }
    tr:hover:not(.description-row) { background-color: #2c2c2c; }
    td code { 
        word-break: break-all; 
        white-space: pre-wrap; 
        background-color: #282828; 
        padding: 3px 6px; 
        border-radius: 4px;
        border: 1px solid #444;
    }
    .description-row { background-color: #252525; }
    .description-cell { padding: 15px 20px !important; border-left: 3px solid #007bff; }
    .description-cell p { margin: 0; line-height: 1.6; }
    .toggle-button { cursor: pointer; font-size: 1.2em; color: #007bff; }
    .severity-CRITICAL { background-color: #dc3545; color: white; font-weight: bold; }
    .severity-HIGH { background-color: #fd7e14; color: white; }
    .severity-MEDIUM { background-color: #ffc107; color: black; }
    .severity-LOW { background-color: #17a2b8; color: white; }
    .severity-UNKNOWN { background-color: #6c757d; color: white; }
    .unfixed { background-color: rgba(220, 53, 69, 0.15) !important; }
    a { color: #00aaff; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .filter-controls { background-color: #2a2a2a; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #333;}
    .filter-controls h3 { margin-top: 0; border: none; }
    .filter-controls select { padding: 8px; font-size: 16px; border-radius: 5px; border: 1px solid #555; background-color: #333; color: #f0f0f0; margin-right: 20px; }
    .filter-buttons button { background-color: #4a4a4a; color: white; border: 1px solid #666; padding: 10px 15px; margin: 2px; border-radius: 5px; cursor: pointer; font-size: 14px; transition: background-color 0.2s; }
    .filter-buttons button:hover { background-color: #5a5a5a; }
    .btn-all { background-color: #007bff; border-color: #007bff; } .btn-all:hover { background-color: #0056b3; }
</style>
<script>
    let currentSeverity = 'ALL';
    let currentCategory = 'ALL';
    function applyFilters() {
        const selectedImage = document.getElementById('imageFilter').value;
        const imageSections = document.querySelectorAll('.image-section');
        imageSections.forEach(section => {
            const isImageVisible = (selectedImage === 'ALL' || section.dataset.imageName === selectedImage);
            section.style.display = isImageVisible ? '' : 'none';
            if (!isImageVisible) return;
            const vulnSection = section.querySelector('.vulnerabilities-section');
            const secretSection = section.querySelector('.secrets-section');
            const misconfigSection = section.querySelector('.misconfigs-section');
            const isVulnVisible = (currentCategory === 'ALL' || currentCategory === 'VULN');
            const isSecretVisible = (currentCategory === 'ALL' || currentCategory === 'SECRET');
            const isMisconfigVisible = (currentCategory === 'ALL' || currentCategory === 'MISCONFIG');
            if (vulnSection) vulnSection.style.display = isVulnVisible ? '' : 'none';
            if (secretSection) secretSection.style.display = isSecretVisible ? '' : 'none';
            if (misconfigSection) misconfigSection.style.display = isMisconfigVisible ? '' : 'none';
            const rows = section.querySelectorAll('tr.finding-row');
            rows.forEach(row => {
                const parentSection = row.closest('div[class$="-section"]');
                const parentVisible = parentSection && parentSection.style.display !== 'none';
                if (parentVisible) {
                    const severityMatch = (currentSeverity === 'ALL' || row.dataset.severity === currentSeverity);
                    row.style.display = severityMatch ? '' : 'none';
                    const descRow = document.getElementById('desc-' + row.id);
                    if (descRow) descRow.style.display = (row.style.display === 'none') ? 'none' : descRow.dataset.initialDisplay;
                } else {
                    row.style.display = 'none';
                    const descRow = document.getElementById('desc-' + row.id);
                    if (descRow) descRow.style.display = 'none';
                }
            });
        });
    }
    function toggleDescription(vulnId) {
        const descRow = document.getElementById('desc-' + vulnId);
        const button = document.getElementById('btn-' + vulnId);
        if (descRow.style.display === 'none') {
            descRow.style.display = '';
            descRow.dataset.initialDisplay = '';
            button.textContent = '(-)';
        } else {
            descRow.style.display = 'none';
            descRow.dataset.initialDisplay = 'none';
            button.textContent = '(+)';
        }
    }
    function filterByCategory(category) { currentCategory = category; applyFilters(); }
    function filterBySeverity(severity) { currentSeverity = severity; applyFilters(); }
    function filterByImage() { applyFilters(); }
</script>
"""

def get_remediation_command(os_family, pkg_name):
    if not pkg_name: return "N/A"
    if os_family in ["debian", "ubuntu"]:
        return f"<code>apt-get install --only-upgrade {pkg_name}</code>"
    if os_family == "alpine":
        return f"<code>apk add --upgrade {pkg_name}</code>"
    if os_family in ["redhat", "centos", "rhel"]:
        return f"<code>yum update {pkg_name}</code>"
    return "Consulte la documentación de su SO."

def create_html_report(json_path, html_path, logo_path=None):
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        print(f"Error: No se pudo leer o encontrar el archivo JSON: {json_path}")
        return

    is_consolidated = 'Reports' in data
    reports = data.get('Reports', [data])
    report_title = data.get('ArtifactName', 'Reporte de Trivy')

    logo_html = ''
    if logo_path and os.path.exists(logo_path):
        correct_logo_path = f"../{logo_path}"
        logo_html = f'<img src="{correct_logo_path}" alt="Company Logo">'
    
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(f"<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'><title>{report_title}</title>{HTML_HEADER}</head><body>")
        f.write(f"<div class='container'><div class='report-header'><h1>Reporte de Seguridad de Infraestructura</h1>{logo_html}</div>")
        
        if is_consolidated:
            f.write(f"<h2>Análisis Consolidado</h2>")
            f.write("<div class='filter-controls'><div><h3>1. Filtrar por Imagen</h3><select id='imageFilter' onchange='filterByImage()'><option value='ALL'>Mostrar Todas las Imágenes</option>")
            image_names = sorted([r.get('ArtifactName') for r in reports if 'ArtifactName' in r])
            for name in image_names:
                f.write(f"<option value='{name}'>{name}</option>")
            f.write("</select></div><div style='margin-top: 20px;'><h3>2. Filtrar por Categoría y Severidad</h3><div class='filter-buttons'><button class='btn-all' onclick=\"filterByCategory('ALL')\">Mostrar Todo</button><button onclick=\"filterByCategory('VULN')\">Vulnerabilidades</button><button onclick=\"filterByCategory('SECRET')\">Secretos</button><button onclick=\"filterByCategory('MISCONFIG')\">Malas Configuraciones</button></div><div class='filter-buttons' style='margin-top: 10px;'><button class='btn-all' onclick=\"filterBySeverity('ALL')\">Todas las Severidades</button><button class='btn-critical' onclick=\"filterBySeverity('CRITICAL')\">Critical</button><button class='btn-high' onclick=\"filterBySeverity('HIGH')\">High</button><button class='btn-medium' onclick=\"filterBySeverity('MEDIUM')\">Medium</button><button class='btn-low' onclick=\"filterBySeverity('LOW')\">Low</button></div></div></div>")

        for i, report in enumerate(reports):
            image_name = report.get('ArtifactName', f'Reporte {i+1}')
            os_family = report.get('Metadata', {}).get('OS', {}).get('Family', 'unknown')
            f.write(f"<div class='image-section' data-image-name='{image_name}'>")
            if is_consolidated: f.write(f"<h2>Activo: {image_name}</h2>")

            results = report.get('Results', [])
            all_vulnerabilities = [v for res in results for v in res.get('Vulnerabilities', [])]
            secrets_with_targets = [{'Target': res.get('Target'), **s} for res in results for s in res.get('Secrets', [])]
            all_misconfigs = [m for res in results for m in res.get('Misconfigurations', [])]

            if not any([all_vulnerabilities, secrets_with_targets, all_misconfigs]): f.write("<p>No se encontraron hallazgos de seguridad.</p>")

            if all_vulnerabilities:
                f.write(f"<div class='vulnerabilities-section'><h3>Vulnerabilidades Encontradas ({len(all_vulnerabilities)})</h3>")
                severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
                sorted_vulnerabilities = sorted(all_vulnerabilities, key=lambda v: severity_order.get(v.get('Severity', 'UNKNOWN'), 5))
                f.write("<table><thead><tr><th style='width:5%'></th><th style='width:15%'>Paquete</th><th style='width:10%'>Severidad</th><th style='width:15%'>Versión Corregida</th><th style='width:30%'>Comando Sugerido</th><th style='width:25%'>Título</th></tr></thead><tbody>")
                for j, vuln in enumerate(sorted_vulnerabilities):
                    vuln_id = f"{i}-{j}"
                    unfixed_class = 'unfixed' if not vuln.get('FixedVersion') else ''
                    severity = vuln.get('Severity', 'UNKNOWN')
                    remediation = get_remediation_command(os_family, vuln.get('PkgName')) if vuln.get('FixedVersion') else "N/A"
                    dependency_html = "".join([f"<br><b>&nbsp;&nbsp;&nbsp;... depende de:</b> {html.escape(dep)}" for dep in vuln.get('DependsOn', [])])
                    f.write(f"<tr id='{vuln_id}' class='finding-row {unfixed_class}' data-severity='{severity}'><td><span id='btn-{vuln_id}' class='toggle-button' onclick=\"toggleDescription('{vuln_id}')\">(+)</span></td><td>{html.escape(vuln.get('PkgName', 'N/A'))}</td><td class='severity-{severity}'>{severity}</td><td>{html.escape(vuln.get('FixedVersion', 'N/A'))}</td><td>{remediation}</td><td>{html.escape(vuln.get('Title', 'N/A'))}</td></tr>")
                    f.write(f"<tr id='desc-{vuln_id}' class='description-row' style='display:none;' data-initial-display='none'><td colspan='6' class='description-cell'><p><b>ID:</b> <a href='{vuln.get('PrimaryURL', '#')}' target='_blank'>{html.escape(vuln.get('VulnerabilityID', 'N/A'))}</a><br><b>Versión Instalada:</b> {html.escape(vuln.get('InstalledVersion', 'N/A'))}<br><b>Descripción:</b> {html.escape(vuln.get('Description', 'No disponible.'))}{dependency_html}</p></td></tr>")
                f.write("</tbody></table></div>")

            if secrets_with_targets:
                f.write(f"<div class='secrets-section'><h3>Secretos Encontrados ({len(secrets_with_targets)})</h3>")
                f.write("<table><thead><tr><th style='width:25%'>Descripción de la Regla</th><th style='width:10%'>Severidad</th><th style='width:30%'>Archivo</th><th style='width:35%'>Línea Sospechosa</th></tr></thead><tbody>")
                for secret in sorted(secrets_with_targets, key=lambda s: s.get('Severity')):
                    severity = secret.get('Severity', 'UNKNOWN')
                    f.write(f"<tr class='finding-row' data-severity='{severity}'><td><b>{html.escape(secret.get('Title', 'N/A'))}</b></td><td class='severity-{severity}'>{severity}</td><td>{html.escape(secret.get('Target', 'N/A'))}</td><td><code>{html.escape(secret.get('Match', 'N/A'))}</code></td></tr>")
                f.write("</tbody></table></div>")

            if all_misconfigs:
                f.write(f"<div class='misconfigs-section'><h3>Malas Configuraciones Encontradas ({len(all_misconfigs)})</h3>")
                f.write("<table><thead><tr><th style='width:25%'>ID de la Regla</th><th style='width:10%'>Severidad</th><th style='width:40%'>Mensaje</th><th style='width:25%'>Resolución</th></tr></thead><tbody>")
                for misconfig in sorted(all_misconfigs, key=lambda m: m.get('Severity')):
                    severity = misconfig.get('Severity', 'UNKNOWN')
                    f.write(f"<tr class='finding-row' data-severity='{severity}'><td><a href='{misconfig.get('PrimaryURL', '#')}' target='_blank'>{html.escape(misconfig.get('ID', 'N/A'))}</a></td><td class='severity-{severity}'>{severity}</td><td>{html.escape(misconfig.get('Message', 'N/A'))}</td><td>{html.escape(misconfig.get('Resolution', 'N/A'))}</td></tr>")
                f.write("</tbody></table></div>")

            f.write("</div>")
        f.write("</div></body></html>")
    print(f"-> Reporte HTML (v7.4 Ejecutivo) generado exitosamente en: {html_path}")

if __name__ == "__main__":
    json_input = sys.argv[1]
    html_output = sys.argv[2]
    logo_path = None
    if len(sys.argv) > 3 and sys.argv[3] == '--logo-path':
        logo_path = sys.argv[4]
    
    create_html_report(json_input, html_output, logo_path)
