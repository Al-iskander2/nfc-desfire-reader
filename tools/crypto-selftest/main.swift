// Autotest de DesfireCrypto. Se compila para macOS (no forma parte de la app iOS):
//
//   cd ios/TagReader7
//   swiftc -import-objc-header Supporting/Bridging-Header.h \
//          Sources/DesfireCrypto.swift tools/crypto-selftest/main.swift -o /tmp/crypto-selftest
//   /tmp/crypto-selftest
//
// Verifica AES-128-CBC contra el vector de NIST SP 800-38A (F.2.1), DES-CBC contra el
// vector oficial de FIPS 81, la equivalencia DES-EDE con la clave repetida, las claves
// de sesion de los cuatro tipos, y simula los protocolos de autenticacion completos
// (AES y legacy) haciendo de tarjeta. Todo esto ANTES de tocar ninguna tarjeta.

import Foundation

setbuf(stdout, nil)   // sin buffer: si algo revienta, no se pierde lo ya impreso

var fallos: [String] = []

func comprobar(_ nombre: String, _ condicion: Bool, _ extra: String = "") {
    print((condicion ? "ok    " : "FALLO ") + nombre + (condicion || extra.isEmpty ? "" : "  -> \(extra)"))
    if !condicion { fallos.append(nombre) }
}

func hex(_ d: Data?) -> String { d?.hex ?? "(nil)" }

/// CCCrypt directo, para poder probar tambien DES de 8 bytes (que desCBC no acepta,
/// porque DESFire lo maneja duplicando la clave).
func cccryptLocal(_ data: Data, key: Data, iv: Data, algorithm: CCAlgorithm) -> Data? {
    let capacity = data.count + kCCBlockSizeAES128
    var out = Data(count: capacity)
    var moved = 0
    let status = out.withUnsafeMutableBytes { outBuf -> CCCryptorStatus in
        data.withUnsafeBytes { dataBuf -> CCCryptorStatus in
            key.withUnsafeBytes { keyBuf -> CCCryptorStatus in
                iv.withUnsafeBytes { ivBuf -> CCCryptorStatus in
                    CCCrypt(CCOperation(kCCEncrypt), algorithm, CCOptions(0),
                            keyBuf.baseAddress, key.count, ivBuf.baseAddress,
                            dataBuf.baseAddress, data.count, outBuf.baseAddress, capacity, &moved)
                }
            }
        }
    }
    guard status == CCCryptorStatus(kCCSuccess) else { return nil }
    return out.prefix(moved)
}

// ── 1. AES-128-CBC: NIST SP 800-38A, F.2.1 ──────────────────────────────────
print("── AES (bloques de 16) ──")
let claveAES = Data(hex: "2b7e151628aed2a6abf7158809cf4f3c")
let ivAES = Data(hex: "000102030405060708090a0b0c0d0e0f")
let claroAES = Data(hex: "6bc1bee22e409f96e93d7e117393172a")
let esperadoNIST = "7649abac8119b246cee98e9b12e9197d"

let cifradoAES = DesfireCrypto.aesCBC(claroAES, key: claveAES, iv: ivAES, encrypt: true)
comprobar("AES-128-CBC cifra el vector NIST", hex(cifradoAES) == esperadoNIST, hex(cifradoAES))
if let c = cifradoAES {
    comprobar("AES descifra y recupera el claro",
              DesfireCrypto.aesCBC(c, key: claveAES, iv: ivAES, encrypt: false) == claroAES)
}
let dosBloques = Data(hex: "6bc1bee22e409f96e93d7e117393172a" + "ae2d8a571e03ac9c9eb76fac45af8e51")
let cifrado2 = DesfireCrypto.aesCBC(dosBloques, key: claveAES, iv: ivAES, encrypt: true)
comprobar("AES-CBC encadena bloques de verdad",
          (cifrado2?.count == 32) && hex(cifrado2).hasPrefix(esperadoNIST), hex(cifrado2))
comprobar("AES rechaza clave de 8 bytes",
          DesfireCrypto.aesCBC(claroAES, key: Data(count: 8), iv: ivAES, encrypt: true) == nil)
comprobar("AES rechaza datos que no son multiplo de 16",
          DesfireCrypto.aesCBC(Data(count: 17), key: claveAES, iv: ivAES, encrypt: true) == nil)

// ── 2. DES-CBC: vector oficial de FIPS 81 ───────────────────────────────────
print()
print("── DES / 3DES (bloques de 8) ──")
let claveDES = Data(hex: "0123456789ABCDEF")
let ivDES = Data(hex: "1234567890ABCDEF")
let claroDES = Data(hex: "4E6F77206973207468652074696D6520666F7220616C6C20")   // "Now is the time for all "
let esperadoFIPS = "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6"

let desDirecto = cccryptLocal(claroDES, key: claveDES, iv: ivDES,
                              algorithm: CCAlgorithm(kCCAlgorithmDES))
comprobar("DES-CBC con kCCAlgorithmDES da el vector FIPS 81",
          hex(desDirecto) == esperadoFIPS, hex(desDirecto))

// DESFire trata DES como DES-EDE con la clave repetida (K||K). Tiene que dar lo mismo.
let claveDESdoblada = claveDES + claveDES
let desDoblado = DesfireCrypto.desCBC(claroDES, key: claveDESdoblada, iv: ivDES, encrypt: true)
comprobar("DES-EDE con K||K = DES simple (mismo vector FIPS 81)",
          hex(desDoblado) == esperadoFIPS, hex(desDoblado))

if let d = desDoblado {
    comprobar("DES descifra y recupera el claro",
              DesfireCrypto.desCBC(d, key: claveDESdoblada, iv: ivDES, encrypt: false) == claroDES)
}

// 2K3DES: clave de 16 bytes de verdad
let clave2k = Data(hex: "0123456789ABCDEF23456789ABCDEF01")
let dosBloquesDES = Data(hex: "4E6F77206973207468652074696D6520666F7220616C6C204E6F772069732074")  // 32 bytes
let cif2k = DesfireCrypto.desCBC(dosBloquesDES, key: clave2k, iv: ivDES, encrypt: true)
comprobar("2K3DES cifra 32 bytes (4 bloques)", cif2k?.count == 32, hex(cif2k))
if let cif2k = cif2k {
    comprobar("2K3DES descifra y recupera el claro",
              DesfireCrypto.desCBC(cif2k, key: clave2k, iv: ivDES, encrypt: false) == dosBloquesDES)
}

// 3K3DES: clave de 24 bytes
let clave3k = Data(hex: "0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123")
let cif3k = DesfireCrypto.desCBC(claroDES, key: clave3k, iv: ivDES, encrypt: true)
comprobar("3K3DES cifra 24 bytes", cif3k?.count == 24, hex(cif3k))
if let cif3k = cif3k {
    comprobar("3K3DES descifra y recupera el claro",
              DesfireCrypto.desCBC(cif3k, key: clave3k, iv: ivDES, encrypt: false) == claroDES)
}

// LA CLAVE POR DEFECTO ES TODO CEROS. Tiene que funcionar, no dar nil.
let cero16 = Data(count: 16)
let cero24 = Data(count: 24)
comprobar("la clave por defecto 2K3DES (16 ceros) cifra",
          DesfireCrypto.desCBC(claroDES, key: cero16, iv: ivDES, encrypt: true) != nil)
comprobar("la clave por defecto 3K3DES (24 ceros) cifra",
          DesfireCrypto.desCBC(claroDES, key: cero24, iv: ivDES, encrypt: true) != nil)
comprobar("desCBC rechaza IV de 16 bytes (los bloques son de 8)",
          DesfireCrypto.desCBC(claroDES, key: cero16, iv: Data(count: 16), encrypt: true) == nil)
comprobar("desCBC rechaza datos que no son multiplo de 8",
          DesfireCrypto.desCBC(Data(count: 9), key: cero16, iv: ivDES, encrypt: true) == nil)

// ── 3. Bits de version en las claves DES/3DES ───────────────────────────────
print()
print("── Bits de version de las claves DES/3DES ──")
comprobar("limpia el bit 0 de cada byte",
          DesfireCrypto.sinBitsDeVersion(Data(hex: "01ABFF03")).hex == "00aafe02",
          DesfireCrypto.sinBitsDeVersion(Data(hex: "01ABFF03")).hex)
comprobar("una clave de ceros se queda igual",
          DesfireCrypto.sinBitsDeVersion(cero16) == cero16)
// La version va en el bit 0 de cada byte, asi que la clave "base" tiene los bytes pares.
let claveBase = Data(hex: "0022446688AACCEE22446688AACCEE00")
func conVersion(_ key: Data, _ version: UInt8) -> Data {
    var out = [UInt8](key)
    var j = 0
    var i = out.count - 1
    while i >= 0 {
        out[i] &= 0xFE
        out[i] |= (version >> UInt8(j)) & 0x01
        i -= 1
        j = (j + 1) % 8
    }
    return Data(out)
}
let conVersion10 = conVersion(claveBase, 0x10)
comprobar("poner la version 0x10 cambia los bits 0",
          conVersion10 != claveBase, conVersion10.hex)
comprobar("quitar la version 0x10 devuelve la clave original",
          DesfireCrypto.sinBitsDeVersion(conVersion10) == claveBase,
          DesfireCrypto.sinBitsDeVersion(conVersion10).hex)

// ── 3b. Expansion de claves para CommonCrypto ───────────────────────────────
print()
print("── Expansion de claves 3DES ──")
comprobar("3K3DES (24) se usa tal cual",
          DesfireCrypto.expandirA24(clave3k) == clave3k)
comprobar("2K3DES (16) se expande a K1||K2||K1",
          DesfireCrypto.expandirA24(clave2k) == clave2k + clave2k.prefix(8),
          hex(DesfireCrypto.expandirA24(clave2k)))
comprobar("DES (8) se expande a K||K||K",
          DesfireCrypto.expandirA24(claveDES) == claveDES + claveDES + claveDES)
comprobar("longitudes raras se rechazan",
          DesfireCrypto.expandirA24(Data(count: 20)) == nil)

// ── 4. Rotacion y claves de sesion de los cuatro tipos ──────────────────────
print()
print("── Rotacion y claves de sesion ──")
comprobar("rotateLeft mueve el primer byte al final",
          DesfireCrypto.rotateLeft(Data(hex: "01020304")).hex == "02030401")
comprobar("rotateLeft no pierde nada con 1 byte",
          DesfireCrypto.rotateLeft(Data(hex: "AB")).hex == "ab")

let rndA = Data(hex: "000102030405060708090a0b0c0d0e0f")
let rndB = Data(hex: "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
comprobar("clave de sesion AES",
          DesfireCrypto.sessionKeyAES(rndA: rndA, rndB: rndB).hex == "00010203f0f1f2f30c0d0e0ffcfdfeff",
          DesfireCrypto.sessionKeyAES(rndA: rndA, rndB: rndB).hex)
comprobar("clave de sesion DES (8)",
          DesfireCrypto.sessionKeyLegacy(rndA: rndA, rndB: rndB, keyLength: 8).hex == "00010203f0f1f2f3",
          DesfireCrypto.sessionKeyLegacy(rndA: rndA, rndB: rndB, keyLength: 8).hex)
comprobar("clave de sesion 2K3DES (16)",
          DesfireCrypto.sessionKeyLegacy(rndA: rndA, rndB: rndB, keyLength: 16).hex == "00010203f0f1f2f304050607f4f5f6f7",
          DesfireCrypto.sessionKeyLegacy(rndA: rndA, rndB: rndB, keyLength: 16).hex)
comprobar("clave de sesion 3K3DES (24)",
          DesfireCrypto.sessionKeyLegacy(rndA: rndA, rndB: rndB, keyLength: 24).hex
          == "00010203f0f1f2f3060708 09f6f7f8f90c0d0e0ffcfdfeff".replacingOccurrences(of: " ", with: ""),
          DesfireCrypto.sessionKeyLegacy(rndA: rndA, rndB: rndB, keyLength: 24).hex)

// ── 5. Simulacion del protocolo AES (haciendo de tarjeta) ───────────────────
print()
print("── Protocolo AES de principio a fin ──")
let clavePrueba = Data(count: 16)
let ivCero16 = Data(count: 16)
let rndBTarjeta = Data(hex: "112233445566778899aabbccddeeff00")
let encRndB = DesfireCrypto.aesCBC(rndBTarjeta, key: clavePrueba, iv: ivCero16, encrypt: true)
comprobar("paso 1: la tarjeta cifra su RndB", encRndB?.count == 16, hex(encRndB))

if let encRndB = encRndB {
    comprobar("paso 1: la app recupera el RndB",
              DesfireCrypto.aesCBC(encRndB, key: clavePrueba, iv: ivCero16, encrypt: false) == rndBTarjeta)
    let rndAPcd = Data(hex: "00112233445566778899aabbccddeeff")
    let bloque = rndAPcd + DesfireCrypto.rotateLeft(rndBTarjeta)
    let encBloque = DesfireCrypto.aesCBC(bloque, key: clavePrueba, iv: encRndB, encrypt: true)
    comprobar("paso 2: la app envia 32 bytes", encBloque?.count == 32)
    if let encBloque = encBloque {
        let recibido = DesfireCrypto.aesCBC(encBloque, key: clavePrueba, iv: encRndB, encrypt: false)
        comprobar("paso 2: la tarjeta reconoce SU RndB rotado",
                  recibido.map { Data($0.suffix(16)) == DesfireCrypto.rotateLeft(rndBTarjeta) } == true)
        let ivPaso3 = Data(encBloque.suffix(16))
        let encRndA = DesfireCrypto.aesCBC(DesfireCrypto.rotateLeft(rndAPcd),
                                           key: clavePrueba, iv: ivPaso3, encrypt: true)
        if let encRndA = encRndA {
            comprobar("AES paso 3: la app VERIFICA el RndA rotado",
                      DesfireCrypto.aesCBC(encRndA, key: clavePrueba, iv: ivPaso3, encrypt: false)
                      == DesfireCrypto.rotateLeft(rndAPcd))
            comprobar("AES: usar los 32 bytes como IV se rechaza (error que cazo el test)",
                      DesfireCrypto.aesCBC(encRndA, key: clavePrueba, iv: encBloque, encrypt: false) == nil)
            comprobar("AES: con clave incorrecta la verificacion NO cuadra",
                      DesfireCrypto.aesCBC(encRndA, key: Data(hex: "ffffffffffffffffffffffffffffffff"),
                                           iv: ivPaso3, encrypt: false)
                      != DesfireCrypto.rotateLeft(rndAPcd))
        }
    }
}

// ── 6. Simulacion del protocolo legacy, 2K3DES y 3K3DES ─────────────────────
print()
print("── Protocolo legacy de principio a fin (8 bytes de bloque) ──")
func simularLegacy(nombre: String, clave: Data) {
    let ivCero8 = Data(count: 8)
    let rndBtarjeta = Data(hex: "1122334455667788")
    guard let encRndB = DesfireCrypto.desCBC(rndBtarjeta, key: clave, iv: ivCero8, encrypt: true) else {
        comprobar("\(nombre): la tarjeta cifra su RndB", false, "nil")
        return
    }
    comprobar("\(nombre): la tarjeta cifra su RndB (8 bytes)", encRndB.count == 8, hex(encRndB))
    let rndBrec = DesfireCrypto.desCBC(encRndB, key: clave, iv: ivCero8, encrypt: false)
    comprobar("\(nombre): la app recupera el RndB", rndBrec == rndBtarjeta, hex(rndBrec))
    guard let rndBrec = rndBrec else { return }

    let rndAapp = Data(hex: "AABBCCDDEEFF0011")
    let bloque = rndAapp + DesfireCrypto.rotateLeft(rndBrec)
    guard let encBloque = DesfireCrypto.desCBC(bloque, key: clave, iv: encRndB, encrypt: true) else {
        comprobar("\(nombre): la app cifra RndA || RndB'", false, "nil")
        return
    }
    comprobar("\(nombre): la app envia 16 bytes", encBloque.count == 16, hex(encBloque))
    let recibido = DesfireCrypto.desCBC(encBloque, key: clave, iv: encRndB, encrypt: false)
    comprobar("\(nombre): la tarjeta reconoce SU RndB rotado",
              recibido.map { Data($0.suffix(8)) == DesfireCrypto.rotateLeft(rndBrec) } == true)

    // Paso 3: la tarjeta responde con el RndA rotado, con el ULTIMO BLOQUE de 8 como IV.
    let ivPaso3 = Data(encBloque.suffix(8))
    guard let encRndA = DesfireCrypto.desCBC(DesfireCrypto.rotateLeft(rndAapp), key: clave,
                                             iv: ivPaso3, encrypt: true) else {
        comprobar("\(nombre): la tarjeta cifra el RndA rotado", false, "nil")
        return
    }
    comprobar("\(nombre): la app VERIFICA el RndA rotado",
              DesfireCrypto.desCBC(encRndA, key: clave, iv: ivPaso3, encrypt: false)
              == DesfireCrypto.rotateLeft(rndAapp))
    comprobar("\(nombre): con clave incorrecta la verificacion NO cuadra",
              DesfireCrypto.desCBC(encRndA, key: Data(repeating: 0xFF, count: clave.count),
                                   iv: ivPaso3, encrypt: false) != DesfireCrypto.rotateLeft(rndAapp))
}

simularLegacy(nombre: "2K3DES (clave por defecto 16 ceros)", clave: cero16)
simularLegacy(nombre: "3K3DES (clave por defecto 24 ceros)", clave: cero24)
simularLegacy(nombre: "DES (clave por defecto 8 ceros, doblada)", clave: Data(count: 8) + Data(count: 8))

print()
if fallos.isEmpty {
    print("Todos los tests PASS")
    exit(0)
} else {
    print("FALLOS: \(fallos.count) -> \(fallos.joined(separator: ", "))")
    exit(1)
}

// ── Utilidad ────────────────────────────────────────────────────────────────
extension Data {
    init(hex: String) {
        let limpio = hex.replacingOccurrences(of: " ", with: "")
        var bytes: [UInt8] = []
        var i = limpio.startIndex
        while i < limpio.endIndex {
            let j = limpio.index(i, offsetBy: 2)
            bytes.append(UInt8(limpio[i..<j], radix: 16) ?? 0)
            i = j
        }
        self = Data(bytes)
    }
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
