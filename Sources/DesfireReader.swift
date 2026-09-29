import Foundation
import Combine
import CoreNFC

// MARK: - Modelos (coinciden con POST /scan de mac/server.py)

struct NFCTransaction: Codable {
    let name: String
    let tx: String
    let rx: String
    let error: String
}

struct NFCScan: Codable {
    let uid: String
    let family: String
    let historical_bytes: String?
    let applications: [String]
    let transactions: [NFCTransaction]
}

// MARK: - Modo de comandos

/// Core NFC expone una DESFire como NFCMiFareTag. Se prueban los dos caminos:
///   - native:  sendMiFareCommand([0x60])                 <- es el que funciona
///   - wrapped: sendMiFareISO7816Command(90 60 00 00 00)  <- falla con "Tag response error"
enum CommandMode: String {
    case native
    case wrapped
    case unknown
}

// MARK: - Codigos de estado DESFire

private let desfireStatusNames: [UInt8: String] = [
    0x00: "OPERATION_OK",
    0x0C: "NO_CHANGES",
    0x0E: "OUT_OF_EEPROM_ERROR",
    0x1C: "ILLEGAL_COMMAND_CODE",
    0x1E: "INTEGRITY_ERROR",
    0x9D: "NO_SUCH_KEY",
    0x9E: "LENGTH_ERROR",
    0x9F: "PERMISSION_DENIED",
    0xA0: "PARAMETER_ERROR",
    0xA1: "APPLICATION_NOT_FOUND",
    0xA2: "APPL_INTEGRITY_ERROR",
    0xAE: "AUTHENTICATION_ERROR",
    0xAF: "ADDITIONAL_FRAME",
    0xBE: "BOUNDARY_ERROR",
    0xCA: "COMMAND_ABORTED",
    0xF0: "FILE_NOT_FOUND",
    0xF1: "FILE_INTEGRITY_ERROR",
]

private func statusName(_ status: UInt8) -> String {
    desfireStatusNames[status] ?? String(format: "0x%02X", status)
}

/// Lector DESFire de SOLO LECTURA.
///
/// Comandos: GetVersion (0x60), GetApplicationIDs (0x6A), SelectApplication (0x5A),
/// GetFileIDs (0x6F), GetFileSettings (0xF5), ReadData (0xBD).
/// NO autentica, NO cambia claves, NO escribe, NO formatea.
final class DesfireReader: NSObject, ObservableObject, NFCTagReaderSessionDelegate {

    @Published var status = "Pulsa LEER TARJETA y acerca la tarjeta."
    @Published var output = ""
    @Published var busy = false
    /// URL del Mac del laboratorio. Viene puesta por defecto, se puede editar en la
    /// pantalla y se recuerda entre lanzamientos.
    static let defaultServerURL = "http://172.20.10.6:8000/scan"
    /// Placeholder viejo: si esta guardado en UserDefaults, se ignora.
    private static let staleServerURL = "192.168.1.50"

    @Published var serverURL: String = DesfireReader.initialServerURL() {
        didSet { UserDefaults.standard.set(serverURL, forKey: "serverURL") }
    }

    static func initialServerURL() -> String {
        if let stored = UserDefaults.standard.string(forKey: "serverURL"),
           !stored.isEmpty, !stored.contains(staleServerURL) {
            return stored
        }
        return defaultServerURL
    }

    private var session: NFCTagReaderSession?
    private var transactions: [NFCTransaction] = []
    private var mode: CommandMode = .unknown

    private let maxFrames = 10
    private let maxApps = 8
    private let maxFiles = 12
    /// Tamano de cada trozo de ReadData y tope total por archivo. Acotado a proposito:
    /// solo queremos ver el principio de cada archivo, no volcar tarjetas enteras.
    private let readChunk = 32
    private let maxReadBytes = 64

    /// Estados DESFire validos. Se usan para DEDUCIR donde va el byte de estado, porque
    /// CoreNFC no es consistente: en la primera respuesta de GetVersion el 0xAF vino
    /// AL PRINCIPIO (AF 04 01 01 01 00 18 05), no al final.
    private static let knownStatuses: Set<UInt8> = [
        0x00, 0x0C, 0x0E, 0x1C, 0x1E, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2,
        0xAE, 0xAF, 0xBE, 0xCA, 0xF0, 0xF1,
    ]

    private func setStatus(_ text: String) {
        DispatchQueue.main.async { self.status = text }
    }

    private func record(name: String, tx: Data, rx: Data?, error: String) {
        transactions.append(NFCTransaction(name: name,
                                           tx: tx.hex,
                                           rx: rx?.hex ?? "",
                                           error: error))
    }

    // MARK: Sesion NFC

    func start() {
        guard NFCTagReaderSession.readingAvailable else {
            setStatus("Este dispositivo no soporta NFCTagReaderSession.")
            return
        }
        transactions = []
        mode = .unknown
        DispatchQueue.main.async {
            self.output = ""
            self.busy = true
        }
        session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
        session?.alertMessage = "Acerca la tarjeta DESFire al telefono."
        session?.begin()
    }

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        DispatchQueue.main.async { self.busy = false }
        let ns = error as NSError
        if ns.code == 200 || ns.code == 204 {
            setStatus("Sesion cerrada. Vuelve a pulsar LEER TARJETA.")
        } else {
            setStatus("Sesion terminada: \(error.localizedDescription)")
        }
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard tags.count == 1 else {
            session.alertMessage = "Presenta una sola tarjeta."
            session.restartPolling()
            return
        }
        let tag = tags[0]
        session.connect(to: tag) { error in
            if let error = error {
                session.invalidate(errorMessage: "No se pudo conectar: \(error.localizedDescription)")
                return
            }
            guard case let .miFare(mifare) = tag else {
                session.invalidate(errorMessage: "La tarjeta no se presento como MIFARE.")
                return
            }
            self.inspect(mifare, session: session)
        }
    }

    // MARK: Separacion del byte de estado

    /// Devuelve (payload, status) sin importar en que extremo venga el estado.
    private func splitStatus(_ raw: Data, mode explicitMode: CommandMode) -> (Data, UInt8) {
        if raw.isEmpty { return (Data(), 0xFF) }
        if raw.count == 1 { return (Data(), raw.first!) }

        // En modo wrapped el APDU siempre devuelve SW1 SW2 al final (ya recortado aparte).
        guard explicitMode != .wrapped else {
            return (Data(raw.dropLast()), raw.last!)
        }

        let first = raw.first!
        let last = raw.last!
        let firstIsStatus = DesfireReader.knownStatuses.contains(first)
        let lastIsStatus = DesfireReader.knownStatuses.contains(last)

        if firstIsStatus && !lastIsStatus { return (Data(raw.dropFirst()), first) }
        if lastIsStatus && !firstIsStatus { return (Data(raw.dropLast()), last) }
        // Ambiguo: los dos extremos parecen estado (tipico en GetFileSettings y ReadData,
        // donde el primer byte de datos es 0x00). Medido en hardware: en este stack el
        // estado va AL PRINCIPIO. Leerlo al reves da tamanos de archivo imposibles
        // (8419 bytes en una tarjeta de 4096); al derecho, la suma de los 11 archivos
        // son 3584 bytes <= 4096. Solo una lectura cuadra con la capacidad del chip.
        if first == 0x00 || first == 0xAF { return (Data(raw.dropFirst()), first) }
        return (Data(raw.dropLast()), last)
    }

    // MARK: Comandos de bajo nivel

    /// Un unico intercambio en un modo CONCRETO. Devuelve (payload, status).
    private func exchange(_ tag: NFCMiFareTag,
                          mode explicitMode: CommandMode,
                          ins: UInt8,
                          data: Data,
                          name: String,
                          done: @escaping (Data, UInt8) -> Void) {
        if explicitMode == .wrapped {
            let apdu = NFCISO7816APDU(instructionClass: 0x90,
                                      instructionCode: ins,
                                      p1Parameter: 0x00,
                                      p2Parameter: 0x00,
                                      data: data,
                                      expectedResponseLength: 256)
            tag.sendMiFareISO7816Command(apdu) { response, sw1, sw2, error in
                let tx = Data([0x90, ins, 0x00, 0x00]) + Data([UInt8(data.count)]) + data + Data([0x00])
                var raw = response
                raw.append(sw1)
                raw.append(sw2)
                self.record(name: name + " [wrapped]", tx: tx, rx: raw,
                            error: error?.localizedDescription ?? "")
                done(response, sw2)
            }
            return
        }

        let packet = Data([ins]) + data
        tag.sendMiFareCommand(commandPacket: packet) { response, error in
            self.record(name: name + " [native]", tx: packet, rx: response,
                        error: error?.localizedDescription ?? "")
            let (payload, status) = self.splitStatus(response, mode: .native)
            done(payload, status)
        }
    }

    private func run(_ tag: NFCMiFareTag,
                     ins: UInt8,
                     data: Data,
                     name: String,
                     done: @escaping (Data, UInt8) -> Void) {
        exchange(tag, mode: mode == .unknown ? .native : mode,
                 ins: ins, data: data, name: name, done: done)
    }

    /// Sigue los frames 0xAF hasta el final. Devuelve todo el payload acumulado.
    private func runFrames(_ tag: NFCMiFareTag,
                           mode explicitMode: CommandMode,
                           ins: UInt8,
                           data: Data,
                           name: String,
                           done: @escaping (Data, UInt8, Int) -> Void) {
        var accumulated = Data()
        var frames = 0
        var finished = false

        func step(_ nextIns: UInt8, _ nextData: Data) {
            if finished { return }
            let label = frames == 0 ? name : "\(name) frame \(frames)"
            exchange(tag, mode: explicitMode, ins: nextIns, data: nextData, name: label) { payload, status in
                if finished { return }
                accumulated.append(payload)
                frames += 1
                if status == 0xAF && frames < self.maxFrames {
                    step(0xAF, Data())
                } else {
                    finished = true
                    done(accumulated, status, frames)
                }
            }
        }

        step(ins, data)
    }

    // MARK: Flujo principal

    private func inspect(_ tag: NFCMiFareTag, session: NFCTagReaderSession) {
        let uid = tag.identifier.hex
        let historical = tag.historicalBytes?.hex

        setStatus("Probando modos de comando...")

        // El sondeo ES el GetVersion: completa los frames y deja la tarjeta limpia.
        // Si el sondeo nativo funciona, ya tenemos la version leida.
        runFrames(tag, mode: .native, ins: 0x60, data: Data(), name: "GetVersion") { version, status, frames in
            if !version.isEmpty {
                self.mode = .native
                self.setStatus("native OK (\(frames) frames, \(version.count) bytes). Leyendo aplicaciones...")
                self.readApplications(tag, uid: uid, historical: historical, version: version, session: session)
                return
            }
            // Plan B: APDUs envueltos con CLA 0x90.
            self.runFrames(tag, mode: .wrapped, ins: 0x60, data: Data(), name: "GetVersion") { version2, _, frames2 in
                self.mode = version2.isEmpty ? .unknown : .wrapped
                self.setStatus("wrapped (\(frames2) frames, \(version2.count) bytes). Leyendo aplicaciones...")
                self.readApplications(tag, uid: uid, historical: historical, version: version2, session: session)
            }
        }
    }

    private func readApplications(_ tag: NFCMiFareTag,
                                  uid: String,
                                  historical: String?,
                                  version: Data,
                                  session: NFCTagReaderSession) {
        runFrames(tag, mode: mode, ins: 0x6A, data: Data(), name: "GetApplicationIDs") { appBytes, status, _ in
            let apps = DesfireReader.parseAIDs(appBytes)
            if apps.isEmpty {
                self.record(name: "GetApplicationIDs [vacio]",
                            tx: Data([0x6A]), rx: appBytes,
                            error: "sin aplicaciones, status final \(statusName(status))")
            }
            self.setStatus("Aplicaciones: \(apps.count). Explorando...")
            self.exploreApplications(tag, apps: apps, index: 0) {
                let scan = NFCScan(uid: uid,
                                   family: "MIFARE DESFire",
                                   historical_bytes: historical,
                                   applications: apps,
                                   transactions: self.transactions)
                self.finish(scan, session: session)
            }
        }
    }

    /// AIDs de 3 bytes sobre el payload ya sin byte de estado.
    static func parseAIDs(_ data: Data) -> [String] {
        guard data.count >= 3 else { return [] }
        var result: [String] = []
        var i = 0
        while i + 3 <= data.count {
            let slice = data[data.startIndex + i ..< data.startIndex + i + 3]
            result.append(slice.map { String(format: "%02X", $0) }.joined())
            i += 3
        }
        return result
    }

    private func exploreApplications(_ tag: NFCMiFareTag,
                                     apps: [String],
                                     index: Int,
                                     done: @escaping () -> Void) {
        guard index < apps.count, index < maxApps else { done(); return }
        let aidHex = apps[index]
        guard let aid = Data(hexString: aidHex), aid.count == 3 else {
            exploreApplications(tag, apps: apps, index: index + 1, done: done)
            return
        }
        run(tag, ins: 0x5A, data: aid, name: "SelectApplication \(aidHex)") { _, _ in
            self.run(tag, ins: 0x6F, data: Data(), name: "GetFileIDs \(aidHex)") { payload, _ in
                self.exploreFiles(tag, aidHex: aidHex, fids: Array(payload), index: 0) {
                    self.exploreApplications(tag, apps: apps, index: index + 1, done: done)
                }
            }
        }
    }

    private func exploreFiles(_ tag: NFCMiFareTag,
                              aidHex: String,
                              fids: [UInt8],
                              index: Int,
                              done: @escaping () -> Void) {
        guard index < fids.count, index < maxFiles else { done(); return }
        let fid = fids[index]
        let fidHex = String(format: "%02X", fid)
        run(tag, ins: 0xF5, data: Data([fid]),
            name: "GetFileSettings \(aidHex) fid \(fidHex)") { settings, _ in
            // GetFileSettings: tipo(1) + comunicacion(1) + access rights(2) +
            // tamano(3, LSB primero). Con el tamano sabemos cuanto leer.
            let bytes = [UInt8](settings)
            var size = 0
            if bytes.count >= 7 {
                size = Int(bytes[4]) | (Int(bytes[5]) << 8) | (Int(bytes[6]) << 16)
            }
            let limit = min(size, self.maxReadBytes)
            self.readFile(tag, aidHex: aidHex, fid: fid, fidHex: fidHex,
                          offset: 0, limit: limit) {
                self.exploreFiles(tag, aidHex: aidHex, fids: fids, index: index + 1, done: done)
            }
        }
    }

    /// Lee el archivo por trozos hasta `limit` bytes. Se detiene en el primer error:
    /// si la clave del archivo no esta, el primer trozo ya devuelve AUTHENTICATION_ERROR.
    private func readFile(_ tag: NFCMiFareTag,
                          aidHex: String,
                          fid: UInt8,
                          fidHex: String,
                          offset: Int,
                          limit: Int,
                          done: @escaping () -> Void) {
        guard offset < limit else { done(); return }
        let len = UInt8(min(Int(readChunk), limit - offset))
        // ReadData: fid(1) + offset(3) + longitud(3), todo LSB primero.
        let request = Data([fid,
                            UInt8((offset >> 16) & 0xFF),
                            UInt8((offset >> 8) & 0xFF),
                            UInt8(offset & 0xFF),
                            len, 0x00, 0x00])
        run(tag, ins: 0xBD, data: request,
            name: "ReadData \(aidHex) fid \(fidHex) off \(offset) len \(len)") { payload, status in
            if status != 0x00 || payload.isEmpty {
                self.record(name: "ReadData \(aidHex) fid \(fidHex) [fin]",
                            tx: Data(), rx: Data(),
                            error: "se detiene aqui: \(statusName(status))")
                done()
                return
            }
            self.readFile(tag, aidHex: aidHex, fid: fid, fidHex: fidHex,
                          offset: offset + Int(len), limit: limit, done: done)
        }
    }

    // MARK: Salida y envio

    private func finish(_ scan: NFCScan, session: NFCTagReaderSession) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let body = try? encoder.encode(scan)
        let jsonText = body.flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
        DispatchQueue.main.async {
            self.output = jsonText
            self.busy = false
        }

        send(body, attempt: 1) { resultado in
            self.setStatus(resultado)
            session.invalidate()
        }
    }

    /// Envia el JSON al Mac. Reintenta una vez si falla, y deja en pantalla la respuesta
    /// del servidor (que incluye el nombre del archivo guardado) para que se sepa si
    /// llego de verdad.
    private func send(_ body: Data?, attempt: Int, done: @escaping (String) -> Void) {
        guard let url = URL(string: serverURL.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = url.scheme, scheme == "http" || scheme == "https" else {
            done("Leido. URL del Mac invalida, no se envio. El JSON queda en pantalla.")
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        request.timeoutInterval = 8

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                if attempt < 2 {
                    self.setStatus("El Mac no respondio, reintentando...")
                    DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) {
                        self.send(body, attempt: attempt + 1, done: done)
                    }
                    return
                }
                done("Leido, pero NO se pudo enviar: \(error.localizedDescription). JSON en pantalla.")
                return
            }
            guard let http = response as? HTTPURLResponse else {
                done("Leido. Respuesta desconocida del servidor.")
                return
            }
            let texto = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            if (200..<300).contains(http.statusCode) {
                done("ENVIADO AL MAC (HTTP \(http.statusCode))  \(texto)")
            } else {
                done("El Mac respondio HTTP \(http.statusCode). JSON en pantalla.")
            }
        }.resume()
    }
}

// MARK: - Hex

extension Data {
    var hex: String {
        map { String(format: "%02X", $0) }.joined()
    }

    init?(hexString: String) {
        let cleaned = hexString.replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: ":", with: "")
        guard cleaned.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        var idx = cleaned.startIndex
        while idx < cleaned.endIndex {
            let next = cleaned.index(idx, offsetBy: 2)
            guard let byte = UInt8(cleaned[idx..<next], radix: 16) else { return nil }
            bytes.append(byte)
            idx = next
        }
        self = Data(bytes)
    }
}
