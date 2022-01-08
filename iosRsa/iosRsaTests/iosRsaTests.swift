import XCTest
@testable import iosRsa

class iosRsaTests: XCTestCase {
    override func setUpWithError() throws {
    }

    override func tearDownWithError() throws {
    }

    func testRsa() throws {
        var error: Unmanaged<CFError>?

        let pubKey = try! getPubKey()

        let message = "Hello from iOS, This is test text".data(using: .utf8)!

        guard let cipher = SecKeyCreateEncryptedData(pubKey, SecKeyAlgorithm.rsaEncryptionPKCS1, message as CFData, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        guard message.count < SecKeyGetBlockSize(pubKey) - 11 else {
            fatalError()
        }

        let data = cipher as Data
        let b64 = data.base64EncodedString()
        print("cipherText(base64): " + b64)
    }

    func getPubKey() throws -> SecKey {
        let pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0nyK3KK6XcTeaGDpombG"
                + "gYyHJ47CczAFOtDWk5EP2gGc17ShU+I1AcIVf27Xsm6uJCf3+zlTaQykrwMUfq9c"
                + "3d4QyIhTZPJyxoE27TIsibQw4CR4D0TCkdWlylp26TSLLBmCRqe+/xZH6+kaAO0j"
                + "Ou6m3eJLvBwr9VI6qNtaztO1QzfibhePCZVIyAVA+PZmcLSfTJpcfwxhaOOthh+u"
                + "475h7r6f50WL/5boEUmaMwRGn8Oi3TMSTSlmOUwni/W4x8iMTEtsQOYs8xYQnYyQ"
                + "LPWQ2hVPCGMBqKl1yktF2OP5Q14zXKSwi5dzvJtQlGVrD1jY9IfYIiL4krhdMXW0"
                + "lQIDAQAB";
        let keyData = Data(base64Encoded: pubkey, options: .ignoreUnknownCharacters)!

        let keyDict: [String: Any] = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecAttrKeyClass): kSecAttrKeyClassPublic,
            String(kSecAttrKeySizeInBits): keyData.count * 8
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        
        print("pubkey: \(key as Any)")
        return key;
    }
}
