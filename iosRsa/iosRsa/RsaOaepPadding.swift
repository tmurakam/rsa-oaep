//
// RSA OAEP Padding implementation
//

import Foundation
import CryptoKit

public enum OAEPDigest {
    case SHA1, SHA256, SHA512

    var length: Int {
        switch self {
        case .SHA1:
            return 160 / 8
        case .SHA256:
            return 256 / 8
        case .SHA512:
             return 512 / 8
        }
    }
}

public enum OAEPError : Error {
    case badLength
    case badPadding
}

/**

 */
public class RsaOAEPPadding {
    var mainDigest: OAEPDigest
    var mgf1Digest: OAEPDigest

    /**
     Initializer
     - Parameters:
       - mainDigest: Main digest algorithm
       - mgf1Digest: MGF1 digest algorithm
     */
    init(mainDigest: OAEPDigest, mgf1Digest: OAEPDigest) {
        self.mainDigest = mainDigest
        self.mgf1Digest = mgf1Digest
    }

    /**
     Pad OAEP padding
     - Parameters:
       - plain: plain message
       - blockSize: Block size (256 for RSA 2048 bits)
     - Returns: OAEP padded block
     - Throws: OAEPError
     */
    func pad(plain: Data, blockSize: Int) throws -> Data {
        let hashLen = mainDigest.length

        // check block size
        let maxMessageLen = blockSize - hashLen * 2 - 2
        guard plain.count <= maxMessageLen else {
            throw OAEPError.badLength
        }

        // calculate lHash
        let lHash = hash(data: Data()/*empty*/, hash: mainDigest)
        //print("lHash = \(dataToString(data: lHash))")

        // calculate padding length
        let psLen = blockSize - hashLen * 2 - 2 - plain.count

        // create DB (data body)
        var db = Data(lHash)
        db.append(Data(count: psLen))
        db.append(0x1)
        db.append(plain)

        // create seed
        var seed = Data(count: hashLen)
        seed.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, hashLen, $0) }

        //print("db: \(dataToString(data: db))")
        //print("seed: \(dataToString(data: seed))")

        // MGF1
        db = xor(data: db, mask: mgf1(maskLength: db.count, seed: seed))
        seed = xor(data: seed, mask: mgf1(maskLength: seed.count, seed: db))

        //print("db: \(dataToString(data: db))")
        //print("seed: \(dataToString(data: seed))")

        var padded = Data()
        padded.append(0x0)
        padded.append(seed)
        padded.append(db)
        return padded
    }

    /**
     Unpad OAEP padding
     - Parameters:
       - padded: OAEP padded block
       - blockSize: Block size
     - Returns: unpadded message
     - Throws: OAEPError
     */
    func unpad(padded: Data) throws -> Data {
        let blockSize = padded.count
        let hashLen = mainDigest.length

        // check first byte is 0?
        guard padded[0] == 0x0 else {
            throw OAEPError.badPadding
        }

        // check message length
        guard blockSize - hashLen * 2 - 2 > 0 else {
            throw OAEPError.badLength
        }

        // Get seed and db
        var seed = padded.subdata(in: 1..<1+hashLen)
        var db = padded.subdata(in: 1+hashLen..<padded.count)
        //print("seed = \(dataToString(data: seed))")
        //print("db = \(dataToString(data: db))")

        // MGF1
        seed = xor(data: seed, mask: mgf1(maskLength: seed.count, seed: db))
        db = xor(data: db, mask: mgf1(maskLength: db.count, seed: seed))

        // Check lHash
        let lHash = hash(data: Data()/*empty*/, hash: mainDigest)
        guard db[0..<hashLen] == lHash else {
            throw OAEPError.badPadding
        }

        // Remove lHash
        db = Data(db.suffix(from: hashLen))

        // Find message start
        for i in 0..<db.count {
            let b = db[i]
            switch b {
            case 0x0:
                // skip pad
                break

            case 0x1:
                // found
                return db.suffix(from: i + 1)

            default:
                // ERROR!
                throw OAEPError.badPadding
            }
        }
        throw OAEPError.badPadding
    }

    /**
     Calculate MGF1 mask
     - Parameters:
       - maskLength: Desired mask length
       - seed: Seed for MGF1 mask
     - Returns: MGF1 mask
     */
    private func mgf1(maskLength: Int, seed: Data) -> Data {
        var mask = Data()

        // Generate MGF1
        var counter: Int = 0
        var remain = maskLength

        var temp = Data()
        temp.append(0x0)
        temp.append(0x0)
        temp.append(0x0)
        temp.append(0x0)
        temp.append(seed)

        while (remain > 0) {
            temp[0] = (UInt8)((counter >> 24) & 0xff)
            temp[1] = (UInt8)((counter >> 16) & 0xff)
            temp[2] = (UInt8)((counter >> 8) & 0xff)
            temp[3] = (UInt8)(counter & 0xff)

            var h = hash(data: temp, hash: mgf1Digest)

            if h.count > remain {
                h = h.prefix(remain)
            }

            mask.append(h)
            remain -= h.count
            counter += 1
        }
        return mask
    }

    private func xor(data: Data, mask: Data) -> Data {
        // XOR
        var result = Data(count: data.count)
        for i in 0..<data.count {
            result[i] = data[i] ^ mask[i]
        }

        return result
    }

    private func hash(data: Data, hash: OAEPDigest) -> Data {
        switch hash {
        case .SHA1:
            return Data(Insecure.SHA1.hash(data: data))
        case .SHA256:
            return Data(SHA256.hash(data: data))
        case .SHA512:
            return Data(SHA512.hash(data: data))
        }
    }

    private func dataToString(data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
