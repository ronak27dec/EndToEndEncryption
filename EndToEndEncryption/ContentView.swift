//
//  ContentView.swift
//  EndToEndEncryption
//
//  Created by Ronak Malick on 09/02/26.
//

import SwiftUI
import CryptoKit

struct ContentView: View {
	var body: some View {
		VStack {
			Image(systemName: "globe")
				.imageScale(.large)
				.foregroundStyle(.tint)
			Text("Hello, world!")
		}
		.task {
			runExample()
		}
		.padding()
	}
	
	// MARK: - Usage Example
	func runExample() {
		let messenger = SecureMessenger()
		
		do {
			// Setup users
			try messenger.setupExampleUsers()
			
			// Alice sends a message to Bob
			let originalMessage = "Hello Bob! This is a secret message from Alice. This is a message f"
			print("\nOriginal message: \(originalMessage)")
			
			// Encrypt
			let encryptedData = try messenger.sendMessage(
				from: "alice",
				to: "bob",
				message: originalMessage
			)
			
			print("\nEncrypted data size: \(encryptedData.count) bytes")
			print("Encrypted (base64): \(encryptedData.base64EncodedString().prefix(50))...")
			
			// Bob receives and decrypts
			let decryptedMessage = try messenger.receiveMessage(
				encryptedData,
				recipientIdentifier: "bob",
				senderIdentifier: "alice"
			)
			
			print("\nDecrypted message: \(decryptedMessage)")
			print("\nSuccess! Messages match: \(originalMessage == decryptedMessage)")
			
		} catch {
			print("Error: \(error.localizedDescription)")
		}
	}
}
