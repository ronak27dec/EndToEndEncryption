//
//  KeyManager.swift
//  EndToEndEncryption
//
//  Created by Ronak Malick on 10/02/26.
//

import Foundation
import CryptoKit

class KeyManager {
    // Generate a new key pair for a user
    static func generateKeyPair() -> (publicKey: P256.KeyAgreement.PublicKey,
                                      privateKey: P256.KeyAgreement.PrivateKey) {
        let privateKey = P256.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        return (publicKey, privateKey)
    }
    
    // Save private key to Keychain
    static func savePrivateKey(_ privateKey: P256.KeyAgreement.PrivateKey,
                               identifier: String) throws {
        let keyData = privateKey.rawRepresentation
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: identifier.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unableToSaveKey
        }
    }
    
    // Load private key from Keychain
    static func loadPrivateKey(identifier: String) throws -> P256.KeyAgreement.PrivateKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: identifier.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecReturnData as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess,
              let keyData = item as? Data else {
            throw KeychainError.keyNotFound
        }
        
        return try P256.KeyAgreement.PrivateKey(rawRepresentation: keyData)
    }
    
    // Save/load public key (usually stored on server or shared with contacts)
    static func savePublicKey(_ publicKey: P256.KeyAgreement.PublicKey,
                              identifier: String) throws {
        let keyData = publicKey.rawRepresentation
        UserDefaults.standard.set(keyData, forKey: "public_key_\(identifier)")
    }
    
    static func loadPublicKey(identifier: String) throws -> P256.KeyAgreement.PublicKey {
        guard let keyData = UserDefaults.standard.data(forKey: "public_key_\(identifier)") else {
            throw KeychainError.keyNotFound
        }
        return try P256.KeyAgreement.PublicKey(rawRepresentation: keyData)
    }
}
