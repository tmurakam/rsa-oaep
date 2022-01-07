import XCTest
@testable import iosRsa

class iosRsaTests: XCTestCase {
    override func setUpWithError() throws {
    }

    override func tearDownWithError() throws {
    }

    func testRsa() throws {
        let pubKey = getPubKey()

        let message = "Hello from iOS, This is test text".data(using: .utf8)!

        var error: Unmanaged<CFError>?
        guard let cipher = SecKeyCreateEncryptedData(pubKey, SecKeyAlgorithm.rsaEncryptionOAEPSHA512, message as CFData, &error) else {
            fatalError()
        }

        let data = cipher as Data
        let b64 = data.base64EncodedString()
        print("cipherText(base64): " + b64)
    }

    func getPubKey() -> SecKey {
        let pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0nyK3KK6XcTeaGDpombG"
                + "gYyHJ47CczAFOtDWk5EP2gGc17ShU+I1AcIVf27Xsm6uJCf3+zlTaQykrwMUfq9c"
                + "3d4QyIhTZPJyxoE27TIsibQw4CR4D0TCkdWlylp26TSLLBmCRqe+/xZH6+kaAO0j"
                + "Ou6m3eJLvBwr9VI6qNtaztO1QzfibhePCZVIyAVA+PZmcLSfTJpcfwxhaOOthh+u"
                + "475h7r6f50WL/5boEUmaMwRGn8Oi3TMSTSlmOUwni/W4x8iMTEtsQOYs8xYQnYyQ"
                + "LPWQ2hVPCGMBqKl1yktF2OP5Q14zXKSwi5dzvJtQlGVrD1jY9IfYIiL4krhdMXW0"
                + "lQIDAQAB";
        let keyData = Data(base64Encoded: pubkey)!

        let keyDict: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: NSNumber(value: keyData.count * 8),
            kSecReturnPersistentRef: true
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, &error) else {
            fatalError()
        }
        return key;
    }
}
