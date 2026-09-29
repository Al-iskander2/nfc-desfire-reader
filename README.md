# NFC DESFire Reader (solo lectura)

App iOS minima para inspeccionar una tarjeta **MIFARE DESFire** desde un **iPhone 7 con
TrollStore**, y mandar el resultado en JSON a un servidor FastAPI en un Mac.

Existe porque Apple no da el entitlement de CoreNFC a las cuentas gratuitas
(`com.apple.developer.nfc.readersession.formats` solo esta en ADP/ADEP, los programas de
pago). Un dispositivo con TrollStore si puede instalarlo, porque TrollStore conserva
**entitlements arbitrarios** al firmar con su certificado falso.

## Que hace exactamente

Comandos DESFire nativos, todos de lectura. No hay autenticacion, no hay escritura, no
hay formateo, no se tocan claves.

| Comando | INS | Para que |
|---|---|---|
| GetVersion | 0x60 | version, memoria, fecha de produccion. Sigue los frames 0xAF |
| GetApplicationIDs | 0x6A | lista de aplicaciones (AIDs) |
| SelectApplication | 0x5A | entra en una aplicacion |
| GetFileIDs | 0x6F | archivos de la aplicacion |
| GetFileSettings | 0xF5 | tipo y permisos del archivo |
| ReadData | 0xBD | contenido del archivo |

Limites duros: 8 frames, 8 aplicaciones, 12 archivos por aplicacion, 16 bytes por
lectura. Una tarjeta con claves contestara `AUTHENTICATION_ERROR` (0xAE) o
`PARAMETER_ERROR` (0xA0) en los comandos que requieran autenticacion: eso NO es un fallo
de la app, es la tarjeta negandose.

### Los dos modos de comando

Core NFC expone una DESFire como `NFCMiFareTag`, y hay dos formas de hablarle:

- **native** — `sendMiFareCommand([0x60])`: comando DESFire crudo.
- **wrapped** — `sendMiFareISO7816Command(90 60 00 00 00)`: la misma orden envuelta en un
  APDU ISO 7816 con CLA 0x90 (la tecnica de libfreefare).

La app **prueba los dos** al empezar y usa el que contesta con status `0x00` u `0xAF`.
Cual funciono te lo dice la pantalla, y ambos intentos quedan en el JSON.

## Compilar (sin instalar Xcode)

1. Sube este repo a GitHub (**publico**: los runners macOS son gratis y sin limite).
2. Pestaña **Actions** → workflow **build-ipa** → **Run workflow**.
3. Cuando acabe, descarga el artefacto `NFCDesfireReader-ipa`.

El workflow hace: `xcodegen generate` → `xcodebuild` (Release, arm64, iOS 15.0) →
`ldid -S` con los entitlements → `NFCDesfireReader.ipa` → sube el artefacto. Ademas
verifica en el log que el entitlement NFC quedo embebido.

## Instalar en el iPhone 7

1. En el iPhone 7, abre el `.ipa` (desde Archivos, Safari, o pasalo por AirDrop) y
   elige **Abrir en TrollStore**. TrollStore lo instala de forma permanente, sin
   caducidad de 7 dias.
2. Al abrirlo por primera vez, iOS pedira permiso de NFC. Acepta.

## Usar

1. En el Mac, arranca el servidor:

       cd mac
       /opt/anaconda3/bin/python3.12 -u -m uvicorn server:app --host 0.0.0.0 --port 8000

2. Mira la IP del Mac: `ipconfig getifaddr en0`
3. En la app, escribe `http://ESA_IP:8000/scan` (se guarda entre lanzamientos).
4. Pulsa **LEER TARJETA** y acerca la tarjeta a la parte de arriba del telefono.
5. El JSON aparece en pantalla **y** aterriza en `mac/nfc_scans/`. Si el envio falla,
   el JSON queda en pantalla igualmente: nada se pierde.

## Estructura

    project.yml                         proyecto Xcode, generado por xcodegen
    Sources/NFCDesfireReaderApp.swift    entrada de la app
    Sources/ContentView.swift            UI: campo de URL, boton, JSON en pantalla
    Sources/DesfireReader.swift          la logica: sesion NFC, comandos, POST
    Supporting/*.plist, *.entitlements   generados por xcodegen (no editar a mano)
    .github/workflows/build-ipa.yml      compilacion en la nube

`NFCDesfireReader.xcodeproj` **no** se versiona: se genera con `xcodegen generate`.

## Seguridad

- Solo lectura por construccion: no hay ni una llamada de escritura.
- Sin autenticacion: no se envian claves, no se adivinan claves.
- `NSAllowsArbitraryLoads` esta activado en el Info.plist porque el laboratorio usa HTTP
  en claro hacia la IP local del Mac. Es una app de laboratorio, no es para la App Store.
