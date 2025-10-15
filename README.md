🛡️ Trivy Report Dashboard: De Scans a Dashboards Ejecutivos

    Transforma los crudos resultados JSON de Trivy en dashboards de seguridad HTML interactivos, modernos y profesionales con un solo comando.

Este sistema no solo ejecuta los escaneos, sino que los enriquece, los organiza y los presenta en un formato listo para el análisis y la toma de decisiones. Es la solución perfecta para equipos de DevOps, seguridad y desarrollo que necesitan claridad y accionabilidad.

<img width="1353" height="1158" alt="imagen" src="https://github.com/user-attachments/assets/9306a2ab-9cd6-4410-858d-481abba6181e" />

¿Por qué usar esta herramienta?

Trivy es una herramienta fantástica, pero su salida estándar está diseñada para la terminal. En un entorno productivo, necesitas más:

    Claridad para todos: Reportes que un manager pueda entender de un vistazo y que un desarrollador pueda usar para remediar.

    Análisis Profundo: La capacidad de filtrar y navegar por cientos de hallazgos de manera eficiente sin perderse en la terminal.

    Acción Rápida: Información contextual para arreglar los problemas, no solo para listarlos.

    Profesionalismo: Reportes personalizados con tu marca que puedes compartir con confianza en toda la organización.

Este sistema fue creado para llenar ese vacío, convirtiendo la data de Trivy en inteligencia accionable.

✨ Características Principales

Este no es un simple script. Es un completo sistema de reportes de seguridad con características de nivel profesional:

    ✅ Dashboard Ejecutivo Moderno: Un reporte con un tema oscuro profesional, diseñado para transmitir tecnología y seriedad.

    ✅ Logo Personalizable: Integra fácilmente el logo de tu empresa para reportes con marca.

    ✅ Escaneo Exhaustivo: Analiza Vulnerabilidades, Secretos y Malas Configuraciones en un solo paso.

    ✅ Filtros Interactivos Avanzados:

        Filtra por Imagen en el reporte consolidado.

        Filtra por Categoría (Vulnerabilidades, Secretos, etc.).

        Filtra por Severidad (Critical, High, Medium, Low).

    ✅ Inteligencia Accionable:

        Comandos de Remediación Sugeridos: Genera automáticamente el comando (apt-get, yum, apk) para parchear cada vulnerabilidad.

        Análisis de Causa Raíz: Muestra el árbol de dependencias para que sepas qué paquete introdujo la librería vulnerable.

        Descripción de CVEs Expandible: Obtén el resumen de cada CVE directamente en el reporte sin tener que abrir una nueva pestaña.

    ✅ Autosuficiente y Portable:

        Instalador Automático de Dependencias: El script verifica e instala Trivy y jq si no los encuentra, garantizando que funcione en casi cualquier sistema Linux o macOS.

    ✅ Parámetros Flexibles: Ejecuta escaneos consolidados, de una sola imagen o filtra por severidad directamente desde la línea de comandos.

🚀 Instalación y Configuración (Plug-and-Play)

Hacer funcionar este sistema es increíblemente simple.

Requisitos Previos

    Docker instalado.

    Python 3 instalado.

El script se encargará del resto.

Pasos

    Clona este repositorio:
    Bash

git clone [https://github.com/tu-usuario/tu-repositorio.git](https://github.com/gearcapitan/Trivy-Report-Dashboard.git)
cd Trivy-Report-Dashboard

(Opcional pero recomendado) Añade tu logo: El script buscará automáticamente cualquier imagen (.png, .jpg, etc.) dentro de una carpeta assets.
Bash

# Crea la carpeta
mkdir assets

# Copia tu logo a la carpeta (el nombre no importa)
cp /ruta/hacia/tu/logo.png assets/

Dale permisos de ejecución al script:
Bash

    chmod +x script.sh

¡Y eso es todo! Estás listo para empezar a escanear. La primera vez que ejecutes el script.sh, este verificará e instalará Trivy y otras herramientas si es necesario.

💻 ¿Cómo Usarlo? (Ejemplos)

El script es flexible y se adapta a tus necesidades. Todos los reportes se generan en la carpeta trivy_reports_html.

1. Generar un Reporte Maestro Consolidado

Este es el modo más potente. Escanea todas tus imágenes de Docker y crea un único dashboard interactivo.
Bash

./script.sh --consolidado

(Graba un GIF corto de esta ejecución y súbelo para un README aún más dinámico)

2. Escanear solo una imagen específica

Perfecto para un análisis rápido de un activo en particular.
Bash

./script.sh --imagen postgres:latest

3. Filtrar por Severidad

Genera reportes que solo contengan los hallazgos más críticos para priorizar tus esfuerzos.
Bash

# Para un reporte consolidado solo con vulnerabilidades HIGH y CRITICAL
./script.sh --consolidado --severidad HIGH,CRITICAL

# Para un reporte individual solo con vulnerabilidades CRITICAL
./script.sh --imagen six2dez/reconftw:main --severidad CRITICAL

4. Ejecución interactiva

Cada vez que ejecutes el script, te preguntará si deseas limpiar los reportes anteriores y si quieres incluir tu logo, dándote control total en cada ejecución.

🛠️ ¿Cómo funciona? (La Arquitectura)

El sistema se compone de dos scripts principales que trabajan en conjunto:

    script.sh (El Orquestador):

        Verifica e instala las dependencias (Trivy, jq).

        Maneja toda la lógica de los parámetros de línea de comandos.

        Ejecuta Trivy con los flags correctos para obtener la máxima cantidad de información (--dependency-tree, --scanners, etc.).

        Une los resultados JSON en un único archivo maestro.

        Llama al script de Python para la renderización final.

    json_to_html.py (El Renderizador):

        Toma los datos JSON crudos.

        Inyecta toda la lógica de visualización: el tema oscuro, los filtros interactivos, las filas expandibles, los comandos de remediación, y la personalización del logo.

        Genera el archivo .html final, que es un dashboard autocontenido y no requiere dependencias externas para ser visualizado.

Este enfoque modular permite que cada componente haga lo que mejor sabe hacer, resultando en un sistema robusto y fácil de mantener.

¡Empieza a transformar tus auditorías de seguridad y lleva tus reportes al siguiente nivel!
