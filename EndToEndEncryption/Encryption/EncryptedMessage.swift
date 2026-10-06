//
//  EncryptedMessage.swift
//  EndToEndEncryption
//
//  Created by Ronak Malick on 10/02/26.
//

import Foundation
import CryptoKit

// MARK: - Data Models
struct EncryptedMessage: Codable {
    let cipherText: Data
    let ephemeralPublicKeyData: Data
    let nonceData: Data
    let tag: Data
    let signature: Data
    
    // Computed properties for CryptoKit types
    var ephemeralPublicKey: P256.KeyAgreement.PublicKey {
        get throws {
            return try P256.KeyAgreement.PublicKey(rawRepresentation: ephemeralPublicKeyData)
        }
    }
    
    var nonce: AES.GCM.Nonce {
        return try! AES.GCM.Nonce(data: nonceData)
    }
    
    // Convert to/from transmission format (JSON)
    func toJSON() throws -> Data {
        return try JSONEncoder().encode(self)
    }
    
    static func fromJSON(_ data: Data) throws -> EncryptedMessage {
        return try JSONDecoder().decode(EncryptedMessage.self, from: data)
    }
}
