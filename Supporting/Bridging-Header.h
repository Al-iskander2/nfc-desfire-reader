// Puente a CommonCrypto. CryptoKit NO tiene AES en modo CBC, y DESFire lo necesita
// (los comandos de autenticacion son CBC con IV explicito).
#import <CommonCrypto/CommonCrypto.h>
