//
//  CryptoEngine.swift
//  EndToEndEncryption
//
//  Created by Ronak Malick on 10/02/26.
//

import Foundation
import CryptoKit

class CryptoEngine {
    
    // MARK: - Message Encryption
    static func encryptMessage(_ message: String,
                               recipientPublicKey: P256.KeyAgreement.PublicKey,
                               senderPrivateKey: P256.KeyAgreement.PrivateKey) throws -> EncryptedMessage {
        
        // Step 1: Generate ephemeral key pair for this session
        let ephemeralPrivateKey = P256.KeyAgreement.PrivateKey()
        
        // Step 2: Perform key agreement
        let sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(
            with: recipientPublicKey
        )
        
        // Step 3: Derive symmetric key from shared secret
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32
        )
        
        // Step 4: Encrypt the message
        let messageData = message.data(using: .utf8)!
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(messageData, using: symmetricKey, nonce: nonce)
        
        // Step 5: Create data to sign (encrypted message + ephemeral public key)
        let dataToSign = sealedBox.ciphertext +
        ephemeralPrivateKey.publicKey.rawRepresentation +
        nonce.data +
        sealedBox.tag
        
        // Step 6: Sign the data
        let signature = try signData(dataToSign,
                                     privateKey: senderPrivateKey)
        
        return EncryptedMessage(
            cipherText: sealedBox.ciphertext,
            ephemeralPublicKeyData: ephemeralPrivateKey.publicKey.rawRepresentation,
            nonceData: nonce.data,
            tag: sealedBox.tag,
            signature: signature
        )
    }
    
    // MARK: - Message Decryption
    static func decryptMessage(_ encryptedMessage: EncryptedMessage,
                               recipientPrivateKey: P256.KeyAgreement.PrivateKey,
                               senderPublicKey: P256.Signing.PublicKey) throws -> String {
        
        // Step 1: Get the ephemeral public key
        let ephemeralPublicKey = try encryptedMessage.ephemeralPublicKey
        
        // Step 2: Create data to verify (same as what was signed)
        let dataToVerify = encryptedMessage.cipherText +
        encryptedMessage.ephemeralPublicKeyData +
        encryptedMessage.nonceData +
        encryptedMessage.tag
        
        // Step 3: Verify signature
        guard try verifySignature(encryptedMessage.signature,
                                  data: dataToVerify,
                                  publicKey: senderPublicKey) else {
            throw CryptoError.signatureVerificationFailed
        }
        
        // Step 4: Perform key agreement with ephemeral public key
        let sharedSecret = try recipientPrivateKey.sharedSecretFromKeyAgreement(
            with: ephemeralPublicKey
        )
        
        // Step 5: Derive symmetric key
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32
        )
        
        // Step 6: Decrypt the message
        let sealedBox = try AES.GCM.SealedBox(
            nonce: encryptedMessage.nonce,
            ciphertext: encryptedMessage.cipherText,
            tag: encryptedMessage.tag
        )
        
        let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)
        
        guard let message = String(data: decryptedData, encoding: .utf8) else {
            throw CryptoError.decryptionFailed
        }
        
        return message
    }
    
    // MARK: - Signing Helper Methods
    private static func signData(_ data: Data,
                                 privateKey: P256.KeyAgreement.PrivateKey) throws -> Data {
        // Convert to signing private key
        let signingPrivateKey = try P256.Signing.PrivateKey(rawRepresentation: privateKey.rawRepresentation)
        let signature = try signingPrivateKey.signature(for: data)
        return signature.rawRepresentation
    }
    
    private static func verifySignature(_ signatureData: Data,
                                        data: Data,
                                        publicKey: P256.Signing.PublicKey) throws -> Bool {
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureData)
        return publicKey.isValidSignature(signature, for: data)
    }
    
    // Helper to convert between key types
    static func convertToSigningPublicKey(from keyAgreementKey: P256.KeyAgreement.PublicKey) throws -> P256.Signing.PublicKey {
        return try P256.Signing.PublicKey(rawRepresentation: keyAgreementKey.rawRepresentation)
    }
    
    static func convertToSigningPrivateKey(from keyAgreementKey: P256.KeyAgreement.PrivateKey) throws -> P256.Signing.PrivateKey {
        return try P256.Signing.PrivateKey(rawRepresentation: keyAgreementKey.rawRepresentation)
    }
}


extension AES.GCM.Nonce {
    var data: Data {
        return Data(self)
    }
}
