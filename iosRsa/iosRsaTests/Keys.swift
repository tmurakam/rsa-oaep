//
// Created by 村上 卓弥 on 2022/01/09.
//

import Foundation

public class Keys {
    public static func getPubKey() throws -> SecKey {
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

    static func getPrivKey() throws -> SecKey {
        let privKey = "MIIEowIBAAKCAQEA0nyK3KK6XcTeaGDpombGgYyHJ47CczAFOtDWk5EP2gGc17Sh\nU+I1AcIVf27Xsm6uJCf3+zlTaQykrwMUfq9c3d4QyIhTZPJyxoE27TIsibQw4CR4\nD0TCkdWlylp26TSLLBmCRqe+/xZH6+kaAO0jOu6m3eJLvBwr9VI6qNtaztO1Qzfi\nbhePCZVIyAVA+PZmcLSfTJpcfwxhaOOthh+u475h7r6f50WL/5boEUmaMwRGn8Oi\n3TMSTSlmOUwni/W4x8iMTEtsQOYs8xYQnYyQLPWQ2hVPCGMBqKl1yktF2OP5Q14z\nXKSwi5dzvJtQlGVrD1jY9IfYIiL4krhdMXW0lQIDAQABAoIBAQCWyXudBcJmzFLc\nCZk1q1THl8l20DGC3ULR2KvvePsXHRKkAJWWBzYb9VL7QIerHtkHs85VncKgPdt4\nOMek3bG0i5IQZoD/jyQkCoszrz7ywzBEUjvkDEkquhgT92y6MdcFl5yZSzBrgyWw\n3gOv6DHV1QObbrL8pl3jV64IK2RJR1o1Iulc8No/NSh/3Goq4FnTJ1oSuOfMfHFH\ngPygglJJ25oulDfoU4p28DrdcpE0s3slWHQo80K49DyrqnevlKrEcV8nRkudjYla\nYjxaOZd3RGEYrnu+ncacpEll26qe1EyjYHA5RSiNjOLqyghSXfi1lvwrIGLBpDYZ\nbMCWxFAdAoGBAOrxA2vL+KKPDQdMANDkfezI9NLy4Mmv/8SfCW4BzfIXzgrV3CEJ\nfOtIgPmbvSCVok/+CnnTzv9H2Dg/D9FjPWV86qR65Yam+ZXVRGPwtN46O1nfjG83\n2D5lXuYbIAXfonIW+IKx/AYMLLQC7fNKau1j6uMdW75ylIk/q5OfHF37AoGBAOVa\nYiTEUbFrewNCAZosZPNc4HsLZCMoGhOWWZ+BAn/k6E7iaOtArWXk3lCTyB/SwtfC\nZIrKewQE5yXgETsYz//LVQ+JnEcK09XfURLL946cHJinKi904mRqdtTsE1ZLXnaM\nweMP87lGtMzCU1QSWoeCPcahVaEBgtJsmivIiIKvAoGAK3zvWC3KWTTHgZlE8WXK\nFWFhSAbjKxIj8t5JXY6B85UKc6EAfTEHaXnjPdDhIj3wbIQmpkRZpZFD6a1qnSSU\ngcusl0OUZudTfbObVDCDGjuHLuydTxz0LyCOf2N3+v5ZUGsGFxMhBnGMeMmuCAG3\nZze+i8msaMVGz1z0wn+KPa8CgYBRHRgcvLnPr51/13ZNmmnRkAVsPukZbfNa/g+Q\nU8YYiVKHo5dLrEInCTx+7uUWLCnwuLVqSJYdI8bEJGyzo+DcLINWzWpRzciBmUtJ\nBI33B8stSeGniwUOUoDYaO2l1V4BO2LO9TNTUWhcClYCI8OUrUE/4IsyOCCWXwZf\nebqdzQKBgEOiAQFi+AkdjoYVTVzmcymTMq0xy/p1eCjR/9b+FNLMX6py4cljiojA\n19GHRzcQ6xYJh3HKe3QSSBcHfQuDeFKioDCAOd6r/wA7UgyUKJqtzrPjT97vVaBo\nqABVY2CZ+JHZ6qq0R8UKVYvHrHtIO17DRkxuvWRe449/xnyY+tl8"
        let keyData = Data(base64Encoded: privKey, options: .ignoreUnknownCharacters)!
        let keyDict: [String: Any] = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecAttrKeyClass): kSecAttrKeyClassPrivate,
            String(kSecAttrKeySizeInBits): keyData.count * 8
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        print("privkey: \(key as Any)")
        return key;
    }
}
