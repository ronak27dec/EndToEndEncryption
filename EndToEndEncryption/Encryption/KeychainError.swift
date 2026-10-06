//
//  KeychainError.swift
//  EndToEndEncryption
//
//  Created by Ronak Malick on 10/02/26.
//

import Foundation

enum KeychainError: Error {
    case unableToSaveKey
    case keyNotFound
    case unexpectedData
}
