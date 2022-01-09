import XCTest
@testable import iosRsa

class iosRsaTests: XCTestCase {
    override func setUpWithError() throws {
    }

    override func tearDownWithError() throws {
    }

    func testRsa() throws {
        var error: Unmanaged<CFError>?

        let pubKey = try! Keys.getPubKey()

        let plain = "Hello from iOS, This is test text"

        guard let cipher = SecKeyCreateEncryptedData(pubKey, SecKeyAlgorithm.rsaEncryptionPKCS1, plain.data(using: .utf8)! as CFData, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        let data = cipher as Data
        let b64 = data.base64EncodedString()
        print("cipherText(base64): " + b64)
    }

    func testOAEPDecrypt() throws {
        var error: Unmanaged<CFError>?

        let plain = "THIS IS TEST TEXT"
        let pubKey = try! Keys.getPubKey()
        let privKey = try! Keys.getPrivKey()

        let padding = RsaOAEPPadding(mainDigest: OAEPDigest.SHA512, mgf1Digest: OAEPDigest.SHA512)
        //let padded = try! padding.pad(plain: message, blockSize: 256)

        guard let cipher = SecKeyCreateEncryptedData(pubKey, SecKeyAlgorithm.rsaEncryptionOAEPSHA512, plain.data(using: .utf8)! as CFData, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        guard let decryptedBlock = SecKeyCreateDecryptedData(privKey, SecKeyAlgorithm.rsaEncryptionRaw, cipher as CFData, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        let decrypted = try! padding.unpad(padded: decryptedBlock as Data)
        let decryptedString = String(data: decrypted, encoding: .utf8)!
        print("decrypted = \(decryptedString)")

        XCTAssertEqual(decryptedString, plain)
    }

    func testOAEPEncrypt() throws {
        var error: Unmanaged<CFError>?

        let plain = "THIS IS TEST TEXT"
        let pubKey = try! Keys.getPubKey()
        let privKey = try! Keys.getPrivKey()

        let padding = RsaOAEPPadding(mainDigest: OAEPDigest.SHA512, mgf1Digest: OAEPDigest.SHA512)
        let padded = try! padding.pad(plain: plain.data(using: .utf8)!, blockSize: 256)

        guard let cipher = SecKeyCreateEncryptedData(pubKey, SecKeyAlgorithm.rsaEncryptionRaw, padded as CFData, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        guard let decrypted = SecKeyCreateDecryptedData(privKey, SecKeyAlgorithm.rsaEncryptionOAEPSHA512, cipher as CFData, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        let decryptedString = String(data: decrypted as Data, encoding: .utf8)!
        print("decrypted = \(decryptedString)")

        XCTAssertEqual(decryptedString, plain)
    }
}
