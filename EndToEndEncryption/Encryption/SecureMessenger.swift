//
//  SecureMessenger.swift
//  EndToEndEncryption
//
//  Created by Ronak Malick on 10/02/26.
//

import Foundation
import CryptoKit

// MARK: - Complete Usage Example
class SecureMessenger {
    // User A sends message to User B
    func sendMessage(from aliceIdentifier: String, to bobIdentifier: String, message: String) throws -> Data {
        do {
            // Generate or load keys for Alice (sender)
            let alicePrivateKey = try KeyManager.loadPrivateKey(identifier: aliceIdentifier)
            
            // In real app, you would fetch this from server/contact list
            // For demo, we'll create Bob's public key
            let bobKeyPair = KeyManager.generateKeyPair()
            try KeyManager.savePublicKey(bobKeyPair.publicKey, identifier: bobIdentifier)
            
            // Encrypt message
            let encrypted = try CryptoEngine.encryptMessage(
                message,
                recipientPublicKey: bobKeyPair.publicKey,
                senderPrivateKey: alicePrivateKey
            )
            
            // Convert to JSON for transmission
            return try encrypted.toJSON()
            
        } catch {
            print("Encryption failed: \(error)")
            throw error
        }
    }
    
    // User B receives message from User A
    func receiveMessage(_ encryptedData: Data,
                        recipientIdentifier: String,
                        senderIdentifier: String) throws -> String {
        do {
            // Load Bob's private key
            let bobPrivateKey = try KeyManager.loadPrivateKey(identifier: recipientIdentifier)
            
            // Load Alice's public key (from server/contact)
            let alicePublicKey = try KeyManager.loadPublicKey(identifier: senderIdentifier)
            
            // Decode encrypted message
            let encryptedMessage = try EncryptedMessage.fromJSON(encryptedData)
            
            // Convert Alice's public key to signing key for verification
            let aliceSigningPublicKey = try CryptoEngine.convertToSigningPublicKey(from: alicePublicKey)
            
            // Decrypt
            let decrypted = try CryptoEngine.decryptMessage(
                encryptedMessage,
                recipientPrivateKey: bobPrivateKey,
                senderPublicKey: aliceSigningPublicKey
            )
            
            return decrypted
            
        } catch {
            print("Decryption failed: \(error)")
            throw error
        }
    }
    
    private func sendToServer(_ data: Data) {
        // Implementation for sending to your server
        // Use URLSession with HTTPS
    }
    
    // Setup example users
    func setupExampleUsers() throws {
        // Setup Alice
        let aliceKeyPair = KeyManager.generateKeyPair()
        try KeyManager.savePrivateKey(aliceKeyPair.privateKey, identifier: "alice")
        try KeyManager.savePublicKey(aliceKeyPair.publicKey, identifier: "alice")
        
        // Setup Bob
        let bobKeyPair = KeyManager.generateKeyPair()
        try KeyManager.savePrivateKey(bobKeyPair.privateKey, identifier: "bob")
        try KeyManager.savePublicKey(bobKeyPair.publicKey, identifier: "bob")
        
        print("Users setup complete")
        print("Alice Public Key: \(aliceKeyPair.publicKey.rawRepresentation.base64EncodedString().prefix(20))...")
        print("Bob Public Key: \(bobKeyPair.publicKey.rawRepresentation.base64EncodedString().prefix(20))...")
    }
}

