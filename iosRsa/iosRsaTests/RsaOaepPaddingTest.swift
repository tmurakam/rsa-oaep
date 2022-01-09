import XCTest
@testable import iosRsa

class RsaOAEPPaddingTest: XCTestCase {
    func testOAEPPadding() {
        let p = RsaOAEPPadding(mainDigest: OAEPDigest.SHA512, mgf1Digest: OAEPDigest.SHA1)

        let plain = "THIS IS TEST".data(using: .utf8)!

        let padded = try! p.pad(plain: plain, blockSize: 256)

        let unpadded = try! p.unpad(padded: padded)
        XCTAssertEqual(unpadded, plain)

        let unpaddedStr = String(data: unpadded, encoding: .utf8)!
        print("Unpadded: \(unpaddedStr)")
    }
}