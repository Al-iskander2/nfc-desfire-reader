import Foundation

/// Primitivas criptograficas que necesita la autenticacion DESFire.
///
/// CryptoKit no ofrece AES en modo CBC, asi que se usa CommonCrypto (llega por el
/// bridging header). DESFire cifra siempre bloques completos: no hay relleno.
enum DesfireCrypto {

    /// AES-128-CBC sin relleno. `iv` es obligatorio y va explicito.
    static func aesCBC(_ data: Data, key: Data, iv: Data, encrypt: Bool) -> Data? {
        guard key.count == 16, iv.count == 16, data.count % 16 == 0, !data.isEmpty else {
            return nil
        }
        let outCapacity = data.count + kCCBlockSizeAES128
        var out = Data(count: outCapacity)
        var moved = 0
        let status = out.withUnsafeMutableBytes { outBuf -> CCCryptorStatus in
            data.withUnsafeBytes { dataBuf -> CCCryptorStatus in
                key.withUnsafeBytes { keyBuf -> CCCryptorStatus in
                    iv.withUnsafeBytes { ivBuf -> CCCryptorStatus in
                        CCCrypt(encrypt ? CCOperation(kCCEncrypt) : CCOperation(kCCDecrypt),
                                CCAlgorithm(kCCAlgorithmAES),
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

    /// DESFire rota un byte a la izquierda: el primer byte pasa al final.
    static func rotateLeft(_ data: Data) -> Data {
        guard let first = data.first, data.count > 1 else { return data }
        return Data(data.dropFirst()) + Data([first])
    }

    /// 16 bytes aleatorios criptograficamente seguros.
    static func randomBytes(_ count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) })
    }

    /// Clave de sesion DESFire (AES): RndA[0..3] || RndB[0..3] || RndA[12..15] || RndB[12..15].
    static func sessionKey(rndA: Data, rndB: Data) -> Data {
        var key = Data()
        key.append(rndA.prefix(4))
        key.append(rndB.prefix(4))
        key.append(rndA.suffix(4))
        key.append(rndB.suffix(4))
        return key
    }
}
