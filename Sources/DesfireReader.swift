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

/// Core NFC expone una DESFire como NFCMiFareTag. Hay dos formas de hablarle y no
/// sabemos a priori cual acepta el telefono, asi que se prueban las dos:
///   - native:  sendMiFareCommand([0x60])            comando DESFire crudo
///   - wrapped: sendMiFareISO7816Command(90 60 00 00 00)  envoltura CLA 0x90
/// La que conteste con status 0x00 o 0xAF (frame adicional) es la buena.
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

// MARK: - Lector

/// Lector DESFire de SOLO LECTURA.
///
/// Solo ejecuta comandos de descubrimiento y lectura:
///   GetVersion (0x60), GetApplicationIDs (0x6A), SelectApplication (0x5A),
///   GetFileIDs (0x6F), GetFileSettings (0xF5), ReadData (0xBD).
///
/// NO autentica, NO cambia claves, NO escribe, NO formatea. Todo acotado:
/// maximo 8 aplicaciones, 12 archivos por aplicacion, 16 bytes por lectura.
final class DesfireReader: NSObject, ObservableObject, NFCTagReaderSessionDelegate {

    @Published var status = "Pulsa LEER TARJETA y acerca la tarjeta."
    @Published var output = ""
    @Published var busy = false
    @Published var serverURL: String =
        UserDefaults.standard.string(forKey: "serverURL") ?? "http://192.168.1.50:8000/scan" {
        didSet { UserDefaults.standard.set(serverURL, forKey: "serverURL") }
    }

    private var session: NFCTagReaderSession?
    private var transactions: [NFCTransaction] = []
    private var mode: CommandMode = .unknown

    // Limites duros de exploracion.
    private let maxFrames = 8
    private let maxApps = 8
    private let maxFiles = 12
    private let readLength: UInt8 = 16

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
        // 200 = user canceled, 204 = session timeout: no son fallos reales.
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

    // MARK: Comandos de bajo nivel

    /// Ejecuta un comando en un modo CONCRETO y devuelve (payload, status).
    /// El payload NO incluye el byte de estado en ningun modo.
    private func execute(_ tag: NFCMiFareTag,
                         mode explicitMode: CommandMode,
                         ins: UInt8,
                         data: Data,
                         name: String,
                         done: @escaping (Data, UInt8, Error?) -> Void) {
        if explicitMode == .wrapped {
            // Este inicializador NO lanza ni devuelve opcional (verificado en la doc
            // de Apple: init(instructionClass:instructionCode:p1Parameter:p2Parameter:
            // data:expectedResponseLength:)).
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
                self.record(name: name + " [wrapped]",
                            tx: tx,
                            rx: raw,
                            error: error?.localizedDescription ?? "")
                done(response, sw2, error)
            }
            return
        }

        // Modo nativo: el byte de estado es el ultimo del paquete de respuesta.
        let packet = Data([ins]) + data
        tag.sendMiFareCommand(commandPacket: packet) { response, error in
            self.record(name: name + " [native]",
                        tx: packet,
                        rx: response,
                        error: error?.localizedDescription ?? "")
            if response.isEmpty {
                done(Data(), 0xFF, error)
                return
            }
            let payload = response.dropLast()
            let status = response.last ?? 0xFF
            done(Data(payload), status, error)
        }
    }

    /// Igual que execute pero usando el modo ya elegido.
    private func run(_ tag: NFCMiFareTag,
                     ins: UInt8,
                     data: Data,
                     name: String,
                     done: @escaping (Data, UInt8, Error?) -> Void) {
        execute(tag, mode: mode == .unknown ? .native : mode, ins: ins, data: data, name: name, done: done)
    }

    /// Prueba ambos modos con GetVersion y decide.
    private func probe(_ tag: NFCMiFareTag, done: @escaping (CommandMode) -> Void) {
        execute(tag, mode: .native, ins: 0x60, data: Data(), name: "probe GetVersion") { p1, s1, e1 in
            let nativeOK = (e1 == nil) && (s1 == 0x00 || s1 == 0xAF)
            let nativeData = (e1 == nil) && !p1.isEmpty
            self.execute(tag, mode: .wrapped, ins: 0x60, data: Data(), name: "probe GetVersion") { p2, s2, e2 in
                let wrappedOK = (e2 == nil) && (s2 == 0x00 || s2 == 0xAF)
                let wrappedData = (e2 == nil) && !p2.isEmpty
                let chosen: CommandMode
                if nativeOK {
                    chosen = .native
                } else if wrappedOK {
                    chosen = .wrapped
                } else if nativeData {
                    chosen = .native
                } else if wrappedData {
                    chosen = .wrapped
                } else {
                    chosen = .unknown
                }
                done(chosen)
            }
        }
    }

    /// Ejecuta un comando siguiendo los frames 0xAF (ADDITIONAL_FRAME) hasta el final.
    /// GetVersion necesita esto: una sola pasada solo devuelve 4 bytes.
    private func runWithFrames(_ tag: NFCMiFareTag,
                               ins: UInt8,
                               data: Data,
                               name: String,
                               done: @escaping (Data) -> Void) {
        var accumulated = Data()
        var frameIndex = 0
        var finished = false

        func step(_ nextIns: UInt8, _ nextData: Data) {
            if finished { return }
            let label = frameIndex == 0 ? name : "\(name) frame \(frameIndex)"
            self.run(tag, ins: nextIns, data: nextData, name: label) { payload, status, error in
                if finished { return }
                accumulated.append(payload)
                frameIndex += 1
                if error != nil && payload.isEmpty {
                    finished = true
                    self.record(name: name + " [fin]", tx: Data(), rx: Data(), error: "abortado: \(statusName(status))")
                    done(accumulated)
                    return
                }
                if status == 0xAF && frameIndex < self.maxFrames {
                    step(0xAF, Data())
                } else {
                    finished = true
                    done(accumulated)
                }
            }
        }

        step(ins, data)
    }

    // MARK: Flujo principal

    private func inspect(_ tag: NFCMiFareTag, session: NFCTagReaderSession) {
        let uid = tag.identifier.hex
        let historical = tag.historicalBytes?.hex

        probe(tag) { chosen in
            self.mode = chosen
            self.setStatus("Comandos: \(chosen.rawValue). Leyendo GetVersion...")

            self.runWithFrames(tag, ins: 0x60, data: Data(), name: "GetVersion") { version in
                self.setStatus("GetVersion: \(version.count) bytes. Leyendo GetApplicationIDs...")

                self.runWithFrames(tag, ins: 0x6A, data: Data(), name: "GetApplicationIDs") { appBytes in
                    let apps = DesfireReader.parseAIDs(appBytes)
                    self.setStatus("Aplicaciones: \(apps.count). Explorando archivos...")

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
        }
    }

    /// AIDs de 3 bytes en el payload ya sin byte de estado.
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
        run(tag, ins: 0x5A, data: aid, name: "SelectApplication \(aidHex)") { _, _, _ in
            self.run(tag, ins: 0x6F, data: Data(), name: "GetFileIDs \(aidHex)") { payload, _, _ in
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
        let tagHex = String(format: "%02X", fid)
        run(tag, ins: 0xF5, data: Data([fid]), name: "GetFileSettings \(aidHex) fid \(tagHex)") { _, _, _ in
            // ReadData: fid(1) + offset(3) + longitud(3)
            let request = Data([fid, 0x00, 0x00, 0x00, self.readLength, 0x00, 0x00])
            self.run(tag, ins: 0xBD, data: request,
                     name: "ReadData \(aidHex) fid \(tagHex) off 0 len \(self.readLength)") { _, _, _ in
                self.exploreFiles(tag, aidHex: aidHex, fids: fids, index: index + 1, done: done)
            }
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

        let trimmed = serverURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed), let scheme = url.scheme,
              scheme == "http" || scheme == "https" else {
            setStatus("Leido. URL del Mac invalida, no se envio. El JSON queda en pantalla.")
            session.invalidate()
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        request.timeoutInterval = 8

        URLSession.shared.dataTask(with: request) { _, response, error in
            if let error = error {
                self.setStatus("Leido, pero no se pudo enviar: \(error.localizedDescription). JSON en pantalla.")
            } else if let http = response as? HTTPURLResponse {
                self.setStatus("Enviado al Mac. HTTP \(http.statusCode).")
            } else {
                self.setStatus("Leido. Respuesta desconocida del servidor.")
            }
            session.invalidate()
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
