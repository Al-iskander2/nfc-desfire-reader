// Autotest de DesfireCrypto. Se compila para macOS (no forma parte de la app iOS):
//
//   cd ios/TagReader7
//   swiftc -import-objc-header Supporting/Bridging-Header.h \
//          Sources/DesfireCrypto.swift tools/crypto-selftest/main.swift -o /tmp/crypto-selftest
//   /tmp/crypto-selftest
//
// Comprueba AES-128-CBC contra el vector oficial de NIST SP 800-38A (F.2.1), la
// rotacion y la clave de sesion de DESFire, y simula el protocolo de autenticacion
// completo haciendo de tarjeta. Si esto pasa, la criptografia esta bien ANTES de
// tocar ninguna tarjeta de verdad.

import Foundation

setbuf(stdout, nil)   // sin buffer: si algo revienta, no se pierde lo ya impreso

var fallos: [String] = []

func comprobar(_ nombre: String, _ condicion: Bool, _ extra: String = "") {
    print((condicion ? "ok    " : "FALLO ") + nombre + (condicion || extra.isEmpty ? "" : "  -> \(extra)"))
    if !condicion { fallos.append(nombre) }
}

func hex(_ d: Data?) -> String { d?.hex ?? "(nil)" }

// ── Vector NIST SP 800-38A, AES-128-CBC, F.2.1 ───────────────────────────────
let clave = Data(hex: "2b7e151628aed2a6abf7158809cf4f3c")
let iv = Data(hex: "000102030405060708090a0b0c0d0e0f")
let claro = Data(hex: "6bc1bee22e409f96e93d7e117393172a")
let esperadoNIST = "7649abac8119b246cee98e9b12e9197d"

comprobar("las utilidades hex cargan bien las claves",
          clave.count == 16 && iv.count == 16 && claro.count == 16,
          "\(clave.count)/\(iv.count)/\(claro.count)")

let cifrado = DesfireCrypto.aesCBC(claro, key: clave, iv: iv, encrypt: true)
comprobar("AES-128-CBC cifra el vector NIST", hex(cifrado) == esperadoNIST, hex(cifrado))

if let cifrado = cifrado {
    let vuelta = DesfireCrypto.aesCBC(cifrado, key: clave, iv: iv, encrypt: false)
    comprobar("descifra y recupera el texto claro", vuelta == claro, hex(vuelta))
}

// Dos bloques: el segundo depende del primero solo si es CBC de verdad.
let dosBloques = Data(hex: "6bc1bee22e409f96e93d7e117393172a" + "ae2d8a571e03ac9c9eb76fac45af8e51")
let cifrado2 = DesfireCrypto.aesCBC(dosBloques, key: clave, iv: iv, encrypt: true)
comprobar("CBC encadena bloques de verdad (2 bloques)",
          (cifrado2?.count == 32) && hex(cifrado2).hasPrefix(esperadoNIST), hex(cifrado2))

// ── Rechazos: mejor nil que basura silenciosa ────────────────────────────────
comprobar("rechaza clave que no sea de 16 bytes",
          DesfireCrypto.aesCBC(claro, key: Data(count: 8), iv: iv, encrypt: true) == nil)
comprobar("rechaza IV que no sea de 16 bytes",
          DesfireCrypto.aesCBC(claro, key: clave, iv: Data(count: 8), encrypt: true) == nil)
comprobar("rechaza datos que no sean multiplo de 16",
          DesfireCrypto.aesCBC(Data(count: 17), key: clave, iv: iv, encrypt: true) == nil)
comprobar("rechaza datos vacios",
          DesfireCrypto.aesCBC(Data(), key: clave, iv: iv, encrypt: true) == nil)

// ── Rotacion y clave de sesion ──────────────────────────────────────────────
comprobar("rotateLeft mueve el primer byte al final",
          DesfireCrypto.rotateLeft(Data(hex: "01020304")).hex == "02030401",
          DesfireCrypto.rotateLeft(Data(hex: "01020304")).hex)
comprobar("rotateLeft no pierde nada con 1 byte",
          DesfireCrypto.rotateLeft(Data(hex: "AB")).hex == "ab")

let rndA = Data(hex: "000102030405060708090a0b0c0d0e0f")
let rndB = Data(hex: "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
let claveSesion = DesfireCrypto.sessionKey(rndA: rndA, rndB: rndB)
comprobar("clave de sesion = RndA[0..3] || RndB[0..3] || RndA[12..15] || RndB[12..15]",
          claveSesion.hex == "00010203f0f1f2f30c0d0e0ffcfdfeff", claveSesion.hex)
comprobar("la clave de sesion son 16 bytes", claveSesion.count == 16, "\(claveSesion.count)")

// ── Simulacion del protocolo completo, haciendo de tarjeta ──────────────────
let clavePrueba = Data(count: 16)                      // la clave por defecto
let rndBTarjeta = Data(hex: "112233445566778899aabbccddeeff00")
let ivCero = Data(count: 16)

// Paso 1: la tarjeta manda E_K(RndB).
let encRndB = DesfireCrypto.aesCBC(rndBTarjeta, key: clavePrueba, iv: ivCero, encrypt: true)
comprobar("paso 1: la tarjeta cifra su RndB", encRndB?.count == 16, hex(encRndB))

if let encRndB = encRndB {
    // La app descifra y comprueba que recupera el RndB.
    let rndBDescifrado = DesfireCrypto.aesCBC(encRndB, key: clavePrueba, iv: ivCero, encrypt: false)
    comprobar("paso 1: la app recupera el RndB", rndBDescifrado == rndBTarjeta, hex(rndBDescifrado))

    // Paso 2: la app manda E_K(RndA || RndB rotado), con IV = el cifrado recibido.
    let rndAPcd = Data(hex: "00112233445566778899aabbccddeeff")
    let bloque = rndAPcd + DesfireCrypto.rotateLeft(rndBTarjeta)
    let encBloque = DesfireCrypto.aesCBC(bloque, key: clavePrueba, iv: encRndB, encrypt: true)
    comprobar("paso 2: la app envia 32 bytes", encBloque?.count == 32, hex(encBloque))

    if let encBloque = encBloque {
        // La tarjeta comprueba que le llega SU RndB rotado.
        let recibido = DesfireCrypto.aesCBC(encBloque, key: clavePrueba, iv: encRndB, encrypt: false)
        comprobar("paso 2: la tarjeta recupera RndA || RndB",
                  recibido == bloque, hex(recibido))
        comprobar("paso 2: la tarjeta reconoce SU RndB rotado",
                  recibido.map { Data($0.suffix(16)) == DesfireCrypto.rotateLeft(rndBTarjeta) } == true)

        // Paso 3: la tarjeta responde con el RndA rotado; la app lo verifica.
        // OJO: el IV aqui es el ULTIMO BLOQUE del cifrado del paso 2, no los 32 bytes.
        let ivPaso3 = Data(encBloque.suffix(16))
        comprobar("paso 3: el IV es de 16 bytes, no los 32 del bloque entero",
                  ivPaso3.count == 16, "\(ivPaso3.count)")
        let encRndA = DesfireCrypto.aesCBC(DesfireCrypto.rotateLeft(rndAPcd),
                                           key: clavePrueba, iv: ivPaso3, encrypt: true)
        comprobar("paso 3: la tarjeta cifra el RndA rotado", encRndA?.count == 16, hex(encRndA))

        if let encRndA = encRndA {
            let verificado = DesfireCrypto.aesCBC(encRndA, key: clavePrueba, iv: ivPaso3, encrypt: false)
            comprobar("paso 3: la app VERIFICA el RndA rotado",
                      verificado == DesfireCrypto.rotateLeft(rndAPcd), hex(verificado))

            // Y con otra clave, la verificacion debe fallar: asi se detecta la mala.
            let conOtraClave = DesfireCrypto.aesCBC(encRndA,
                                                    key: Data(hex: "ffffffffffffffffffffffffffffffff"),
                                                    iv: ivPaso3, encrypt: false)
            comprobar("con clave incorrecta la verificacion NO cuadra",
                      conOtraClave != DesfireCrypto.rotateLeft(rndAPcd), hex(conOtraClave))

            // Y el error que cazo el test: usar los 32 bytes como IV tiene que dar nil
            // en vez de colarse.
            comprobar("usar los 32 bytes como IV lo rechaza aesCBC",
                      DesfireCrypto.aesCBC(encRndA, key: clavePrueba, iv: encBloque, encrypt: false) == nil)
        }
    }
}

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
