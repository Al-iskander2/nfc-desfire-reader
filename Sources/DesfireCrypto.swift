import Foundation

/// Primitivas criptograficas que necesita DESFire: AES-CBC (16 bytes de bloque) y
/// DES / 2K3DES / 3K3DES-CBC (8 bytes de bloque).
///
/// CryptoKit no ofrece CBC, asi que se usa CommonCrypto (llega por el bridging header).
/// DESFire cifra siempre bloques completos: no hay relleno.
///
/// El detalle de los DES/3DES va segun la implementacion de referencia nfcjlib
/// (skjolber/desfire-tools-for-android, DESFireEV1.java):
///   - Los tres van con kCCAlgorithm3DES. DES-EDE con la clave repetida (K||K) equivale
///     a DES simple, y es como lo trata DESFire.
///   - En las claves DES/3DES la version va en el BIT 0 de cada byte de la clave, asi
///     que hay que limpiarlo antes de usarla.
enum DesfireCrypto {

    // MARK: AES (bloques de 16)

    static func aesCBC(_ data: Data, key: Data, iv: Data, encrypt: Bool) -> Data? {
        guard key.count == 16, iv.count == 16, data.count % 16 == 0, !data.isEmpty else {
            return nil
        }
        return cccrypt(data, key: key, iv: iv, algorithm: CCAlgorithm(kCCAlgorithmAES),
                       encrypt: encrypt)
    }

    // MARK: DES / 2K3DES / 3K3DES (bloques de 8)

    /// DES / 2K3DES / 3K3DES en CBC, bloques de 8 bytes.
    ///
    /// CommonCrypto SOLO acepta claves de 24 bytes para 3DES (kCCKeySize3DES = 24) y
    /// rechaza las de 16 con kCCParamError. Asi que hay que expandir:
    ///   24 bytes (3K3DES) -> se usa tal cual
    ///   16 bytes (2K3DES) -> K1||K2||K1  (que es justo lo que significa 2K3DES)
    ///    8 bytes (DES)    -> K||K||K     (DES-EDE con la misma clave = DES simple)
    ///
    /// Esto lo cazo el autotest: sin expandir, toda clave de 16 bytes devolvia nil y una
    /// clave correcta se habria reportado como incorrecta.
    static func desCBC(_ data: Data, key: Data, iv: Data, encrypt: Bool) -> Data? {
        guard let clave24 = expandirA24(key) else { return nil }
        guard iv.count == 8, data.count % 8 == 0, !data.isEmpty else { return nil }
        return cccrypt(data, key: clave24, iv: iv, algorithm: CCAlgorithm(kCCAlgorithm3DES),
                       encrypt: encrypt)
    }

    /// Lleva una clave DES/2K3DES/3K3DES a los 24 bytes que exige CommonCrypto.
    static func expandirA24(_ key: Data) -> Data? {
        switch key.count {
        case 24:
            return key
        case 16:
            return key + key.prefix(8)          // K1||K2||K1
        case 8:
            return key + key + key              // K||K||K
        default:
            return nil
        }
    }

    /// En DES/3DES la version de la clave vive en el bit 0 de cada byte. Antes de usarla
    /// hay que limpiarlo, o el cifrado no cuadra. Con una clave 00..00 no cambia nada,
    /// pero con cualquier otra es imprescindible.
    static func sinBitsDeVersion(_ key: Data) -> Data {
        Data(key.map { $0 & 0xFE })
    }

    // MARK: Comunes

    /// Rotacion a la izquierda de un byte: el primero pasa al final. La usan los tres
    /// protocolos (AES y legacy) igual.
    static func rotateLeft(_ data: Data) -> Data {
        guard let first = data.first, data.count > 1 else { return data }
        return Data(data.dropFirst()) + Data([first])
    }

    static func randomBytes(_ count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) })
    }

    /// Clave de sesion AES: RndA[0..3] || RndB[0..3] || RndA[12..15] || RndB[12..15].
    static func sessionKeyAES(rndA: Data, rndB: Data) -> Data {
        var key = Data()
        key.append(rndA.prefix(4))
        key.append(rndB.prefix(4))
        key.append(rndA.suffix(4))
        key.append(rndB.suffix(4))
        return key
    }

    /// Clave de sesion legacy, segun la longitud de clave:
    ///   DES    (8)  : RndA[0..3] || RndB[0..3]
    ///   2K3DES (16) : RndA[0..3] || RndB[0..3] || RndA[4..7] || RndB[4..7]
    ///   3K3DES (24) : RndA[0..3] || RndB[0..3] || RndA[6..9] || RndB[6..9]
    ///                 || RndA[12..15] || RndB[12..15]
    static func sessionKeyLegacy(rndA: Data, rndB: Data, keyLength: Int) -> Data {
        func trozo(_ d: Data, _ desde: Int, _ cuantos: Int) -> Data {
            Data(d[d.index(d.startIndex, offsetBy: desde)..<d.index(d.startIndex, offsetBy: desde + cuantos)])
        }
        var key = Data()
        if keyLength == 8 {
            key.append(trozo(rndA, 0, 4)); key.append(trozo(rndB, 0, 4))
        } else if keyLength == 24 {
            key.append(trozo(rndA, 0, 4)); key.append(trozo(rndB, 0, 4))
            key.append(trozo(rndA, 6, 4)); key.append(trozo(rndB, 6, 4))
            key.append(trozo(rndA, 12, 4)); key.append(trozo(rndB, 12, 4))
        } else {
            key.append(trozo(rndA, 0, 4)); key.append(trozo(rndB, 0, 4))
            key.append(trozo(rndA, 4, 4)); key.append(trozo(rndB, 4, 4))
        }
        return key
    }

    /// Un solo sitio para llamar a CommonCrypto. Devuelve nil si algo no cuadra, en vez
    /// de colar bytes malos.
    private static func cccrypt(_ data: Data, key: Data, iv: Data,
                                algorithm: CCAlgorithm, encrypt: Bool) -> Data? {
        let outCapacity = data.count + kCCBlockSizeAES128
        var out = Data(count: outCapacity)
        var moved = 0
        let status = out.withUnsafeMutableBytes { outBuf -> CCCryptorStatus in
            data.withUnsafeBytes { dataBuf -> CCCryptorStatus in
                key.withUnsafeBytes { keyBuf -> CCCryptorStatus in
                    iv.withUnsafeBytes { ivBuf -> CCCryptorStatus in
                        CCCrypt(encrypt ? CCOperation(kCCEncrypt) : CCOperation(kCCDecrypt),
                                algorithm,
                                CCOptions(0),                       // 0 = CBC, IV explicito
                                keyBuf.baseAddress, key.count,
                                ivBuf.baseAddress,
                                dataBuf.baseAddress, data.count,
                                outBuf.baseAddress, outCapacity,
                                &moved)
                    }
                }
            }
        }
        guard status == CCCryptorStatus(kCCSuccess) else { return nil }
        return out.prefix(moved)
    }
}
