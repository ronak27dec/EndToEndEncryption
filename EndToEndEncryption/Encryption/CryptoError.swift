//
//  CryptoError.swift
//  EndToEndEncryption
//
//  Created by Ronak Malick on 10/02/26.
//

import Foundation

// MARK: - Error Handling
enum CryptoError: Error {
    case encryptionFailed
    case decryptionFailed
    case keyGenerationFailed
    case signatureVerificationFailed
}
