//
//  ContentView.swift
//  swype-bitcoin
//
//  Created by Raj Khare on 3/23/22.
//

import SwiftUI
import CryptoSwift
import CryptoKit
import secp256k1
@testable import Bech32

/// RIPEMD160 hash function implementation
/// https://stackoverflow.com/questions/43091858/swift-hash-a-string-using-hash-hmac-with-ripemd160/43193583#43193583
public struct RIPEMD160 {
    private var MDbuf: (UInt32, UInt32, UInt32, UInt32, UInt32)
    private var buffer: Data
    private var count: Int64 // Total # of bytes processed.

    public init() {
        MDbuf = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)
        buffer = Data()
        count = 0
    }

    private mutating func compress(_ X: UnsafePointer<UInt32>) {

        // *** Helper functions (originally macros in rmd160.h) ***

        /* ROL(x, n) cyclically rotates x over n bits to the left */
        /* x must be of an unsigned 32 bits type and 0 <= n < 32. */
        func ROL(_ x: UInt32, _ n: UInt32) -> UInt32 {
            return (x << n) | ( x >> (32 - n))
        }

        /* the five basic functions F(), G() and H() */

        func F(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
            return x ^ y ^ z
        }

        func G(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
            return (x & y) | (~x & z)
        }

        func H(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
            return (x | ~y) ^ z
        }

        func I(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
            return (x & z) | (y & ~z)
        }

        func J(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
            return x ^ (y | ~z)
        }

        /* the ten basic operations FF() through III() */

        func FF(_ a: inout UInt32, _ b: UInt32, _ c: inout UInt32, _ d: UInt32, _ e: UInt32, _ x: UInt32, _ s: UInt32) {
            a = a &+ F(b, c, d) &+ x
            a = ROL(a, s) &+ e
            c = ROL(c, 10)
        }

        func GG(_ a: inout UInt32, _ b: UInt32, _ c: inout UInt32, _ d: UInt32, _ e: UInt32, _ x: UInt32, _ s: UInt32) {
            a = a &+ G(b, c, d) &+ x &+ 0x5a827999
            a = ROL(a, s) &+ e
            c = ROL(c, 10)
        }

        func HH(_ a: inout UInt32, _ b: UInt32, _ c: inout UInt32, _ d: UInt32, _ e: UInt32, _ x: UInt32, _ s: UInt32) {
            a = a &+ H(b, c, d) &+ x &+ 0x6ed9eba1
            a = ROL(a, s) &+ e
            c = ROL(c, 10)
        }

        func II(_ a: inout UInt32, _ b: UInt32, _ c: inout UInt32, _ d: UInt32, _ e: UInt32, _ x: UInt32, _ s: UInt32) {
            a = a &+ I(b, c, d) &+ x &+ 0x8f1bbcdc
            a = ROL(a, s) &+ e
            c = ROL(c, 10)
        }

        func JJ(_ a: inout UInt32, _ b: UInt32, _ c: inout UInt32, _ d: UInt32, _ e: UInt32, _ x: UInt32, _ s: UInt32) {
            a = a &+ J(b, c, d) &+ x &+ 0xa953fd4e
            a = ROL(a, s) &+ e
            c = ROL(c, 10)
        }

        func FFF(_ a: inout UInt32, _ b: UInt32, _ c: inout UInt32, _ d: UInt32, _ e: UInt32, _ x: UInt32, _ s: UInt32) {
            a = a &+ F(b, c, d) &+ x
            a = ROL(a, s) &+ e
            c = ROL(c, 10)
        }

        func GGG(_ a: inout UInt32, _ b: UInt32, _ c: inout UInt32, _ d: UInt32, _ e: UInt32, _ x: UInt32, _ s: UInt32) {
            a = a &+ G(b, c, d) &+ x &+ 0x7a6d76e9
            a = ROL(a, s) &+ e
            c = ROL(c, 10)
        }

        func HHH(_ a: inout UInt32, _ b: UInt32, _ c: inout UInt32, _ d: UInt32, _ e: UInt32, _ x: UInt32, _ s: UInt32) {
            a = a &+ H(b, c, d) &+ x &+ 0x6d703ef3
            a = ROL(a, s) &+ e
            c = ROL(c, 10)
        }

        func III(_ a: inout UInt32, _ b: UInt32, _ c: inout UInt32, _ d: UInt32, _ e: UInt32, _ x: UInt32, _ s: UInt32) {
            a = a &+ I(b, c, d) &+ x &+ 0x5c4dd124
            a = ROL(a, s) &+ e
            c = ROL(c, 10)
        }

        func JJJ(_ a: inout UInt32, _ b: UInt32, _ c: inout UInt32, _ d: UInt32, _ e: UInt32, _ x: UInt32, _ s: UInt32) {
            a = a &+ J(b, c, d) &+ x &+ 0x50a28be6
            a = ROL(a, s) &+ e
            c = ROL(c, 10)
        }

        // *** The function starts here ***

        var (aa, bb, cc, dd, ee) = MDbuf
        var (aaa, bbb, ccc, ddd, eee) = MDbuf

        /* round 1 */
        FF(&aa, bb, &cc, dd, ee, X[ 0], 11)
        FF(&ee, aa, &bb, cc, dd, X[ 1], 14)
        FF(&dd, ee, &aa, bb, cc, X[ 2], 15)
        FF(&cc, dd, &ee, aa, bb, X[ 3], 12)
        FF(&bb, cc, &dd, ee, aa, X[ 4],  5)
        FF(&aa, bb, &cc, dd, ee, X[ 5],  8)
        FF(&ee, aa, &bb, cc, dd, X[ 6],  7)
        FF(&dd, ee, &aa, bb, cc, X[ 7],  9)
        FF(&cc, dd, &ee, aa, bb, X[ 8], 11)
        FF(&bb, cc, &dd, ee, aa, X[ 9], 13)
        FF(&aa, bb, &cc, dd, ee, X[10], 14)
        FF(&ee, aa, &bb, cc, dd, X[11], 15)
        FF(&dd, ee, &aa, bb, cc, X[12],  6)
        FF(&cc, dd, &ee, aa, bb, X[13],  7)
        FF(&bb, cc, &dd, ee, aa, X[14],  9)
        FF(&aa, bb, &cc, dd, ee, X[15],  8)

        /* round 2 */
        GG(&ee, aa, &bb, cc, dd, X[ 7],  7)
        GG(&dd, ee, &aa, bb, cc, X[ 4],  6)
        GG(&cc, dd, &ee, aa, bb, X[13],  8)
        GG(&bb, cc, &dd, ee, aa, X[ 1], 13)
        GG(&aa, bb, &cc, dd, ee, X[10], 11)
        GG(&ee, aa, &bb, cc, dd, X[ 6],  9)
        GG(&dd, ee, &aa, bb, cc, X[15],  7)
        GG(&cc, dd, &ee, aa, bb, X[ 3], 15)
        GG(&bb, cc, &dd, ee, aa, X[12],  7)
        GG(&aa, bb, &cc, dd, ee, X[ 0], 12)
        GG(&ee, aa, &bb, cc, dd, X[ 9], 15)
        GG(&dd, ee, &aa, bb, cc, X[ 5],  9)
        GG(&cc, dd, &ee, aa, bb, X[ 2], 11)
        GG(&bb, cc, &dd, ee, aa, X[14],  7)
        GG(&aa, bb, &cc, dd, ee, X[11], 13)
        GG(&ee, aa, &bb, cc, dd, X[ 8], 12)

        /* round 3 */
        HH(&dd, ee, &aa, bb, cc, X[ 3], 11)
        HH(&cc, dd, &ee, aa, bb, X[10], 13)
        HH(&bb, cc, &dd, ee, aa, X[14],  6)
        HH(&aa, bb, &cc, dd, ee, X[ 4],  7)
        HH(&ee, aa, &bb, cc, dd, X[ 9], 14)
        HH(&dd, ee, &aa, bb, cc, X[15],  9)
        HH(&cc, dd, &ee, aa, bb, X[ 8], 13)
        HH(&bb, cc, &dd, ee, aa, X[ 1], 15)
        HH(&aa, bb, &cc, dd, ee, X[ 2], 14)
        HH(&ee, aa, &bb, cc, dd, X[ 7],  8)
        HH(&dd, ee, &aa, bb, cc, X[ 0], 13)
        HH(&cc, dd, &ee, aa, bb, X[ 6],  6)
        HH(&bb, cc, &dd, ee, aa, X[13],  5)
        HH(&aa, bb, &cc, dd, ee, X[11], 12)
        HH(&ee, aa, &bb, cc, dd, X[ 5],  7)
        HH(&dd, ee, &aa, bb, cc, X[12],  5)

        /* round 4 */
        II(&cc, dd, &ee, aa, bb, X[ 1], 11)
        II(&bb, cc, &dd, ee, aa, X[ 9], 12)
        II(&aa, bb, &cc, dd, ee, X[11], 14)
        II(&ee, aa, &bb, cc, dd, X[10], 15)
        II(&dd, ee, &aa, bb, cc, X[ 0], 14)
        II(&cc, dd, &ee, aa, bb, X[ 8], 15)
        II(&bb, cc, &dd, ee, aa, X[12],  9)
        II(&aa, bb, &cc, dd, ee, X[ 4],  8)
        II(&ee, aa, &bb, cc, dd, X[13],  9)
        II(&dd, ee, &aa, bb, cc, X[ 3], 14)
        II(&cc, dd, &ee, aa, bb, X[ 7],  5)
        II(&bb, cc, &dd, ee, aa, X[15],  6)
        II(&aa, bb, &cc, dd, ee, X[14],  8)
        II(&ee, aa, &bb, cc, dd, X[ 5],  6)
        II(&dd, ee, &aa, bb, cc, X[ 6],  5)
        II(&cc, dd, &ee, aa, bb, X[ 2], 12)

        /* round 5 */
        JJ(&bb, cc, &dd, ee, aa, X[ 4],  9)
        JJ(&aa, bb, &cc, dd, ee, X[ 0], 15)
        JJ(&ee, aa, &bb, cc, dd, X[ 5],  5)
        JJ(&dd, ee, &aa, bb, cc, X[ 9], 11)
        JJ(&cc, dd, &ee, aa, bb, X[ 7],  6)
        JJ(&bb, cc, &dd, ee, aa, X[12],  8)
        JJ(&aa, bb, &cc, dd, ee, X[ 2], 13)
        JJ(&ee, aa, &bb, cc, dd, X[10], 12)
        JJ(&dd, ee, &aa, bb, cc, X[14],  5)
        JJ(&cc, dd, &ee, aa, bb, X[ 1], 12)
        JJ(&bb, cc, &dd, ee, aa, X[ 3], 13)
        JJ(&aa, bb, &cc, dd, ee, X[ 8], 14)
        JJ(&ee, aa, &bb, cc, dd, X[11], 11)
        JJ(&dd, ee, &aa, bb, cc, X[ 6],  8)
        JJ(&cc, dd, &ee, aa, bb, X[15],  5)
        JJ(&bb, cc, &dd, ee, aa, X[13],  6)

        /* parallel round 1 */
        JJJ(&aaa, bbb, &ccc, ddd, eee, X[ 5],  8)
        JJJ(&eee, aaa, &bbb, ccc, ddd, X[14],  9)
        JJJ(&ddd, eee, &aaa, bbb, ccc, X[ 7],  9)
        JJJ(&ccc, ddd, &eee, aaa, bbb, X[ 0], 11)
        JJJ(&bbb, ccc, &ddd, eee, aaa, X[ 9], 13)
        JJJ(&aaa, bbb, &ccc, ddd, eee, X[ 2], 15)
        JJJ(&eee, aaa, &bbb, ccc, ddd, X[11], 15)
        JJJ(&ddd, eee, &aaa, bbb, ccc, X[ 4],  5)
        JJJ(&ccc, ddd, &eee, aaa, bbb, X[13],  7)
        JJJ(&bbb, ccc, &ddd, eee, aaa, X[ 6],  7)
        JJJ(&aaa, bbb, &ccc, ddd, eee, X[15],  8)
        JJJ(&eee, aaa, &bbb, ccc, ddd, X[ 8], 11)
        JJJ(&ddd, eee, &aaa, bbb, ccc, X[ 1], 14)
        JJJ(&ccc, ddd, &eee, aaa, bbb, X[10], 14)
        JJJ(&bbb, ccc, &ddd, eee, aaa, X[ 3], 12)
        JJJ(&aaa, bbb, &ccc, ddd, eee, X[12],  6)

        /* parallel round 2 */
        III(&eee, aaa, &bbb, ccc, ddd, X[ 6],  9)
        III(&ddd, eee, &aaa, bbb, ccc, X[11], 13)
        III(&ccc, ddd, &eee, aaa, bbb, X[ 3], 15)
        III(&bbb, ccc, &ddd, eee, aaa, X[ 7],  7)
        III(&aaa, bbb, &ccc, ddd, eee, X[ 0], 12)
        III(&eee, aaa, &bbb, ccc, ddd, X[13],  8)
        III(&ddd, eee, &aaa, bbb, ccc, X[ 5],  9)
        III(&ccc, ddd, &eee, aaa, bbb, X[10], 11)
        III(&bbb, ccc, &ddd, eee, aaa, X[14],  7)
        III(&aaa, bbb, &ccc, ddd, eee, X[15],  7)
        III(&eee, aaa, &bbb, ccc, ddd, X[ 8], 12)
        III(&ddd, eee, &aaa, bbb, ccc, X[12],  7)
        III(&ccc, ddd, &eee, aaa, bbb, X[ 4],  6)
        III(&bbb, ccc, &ddd, eee, aaa, X[ 9], 15)
        III(&aaa, bbb, &ccc, ddd, eee, X[ 1], 13)
        III(&eee, aaa, &bbb, ccc, ddd, X[ 2], 11)

        /* parallel round 3 */
        HHH(&ddd, eee, &aaa, bbb, ccc, X[15],  9)
        HHH(&ccc, ddd, &eee, aaa, bbb, X[ 5],  7)
        HHH(&bbb, ccc, &ddd, eee, aaa, X[ 1], 15)
        HHH(&aaa, bbb, &ccc, ddd, eee, X[ 3], 11)
        HHH(&eee, aaa, &bbb, ccc, ddd, X[ 7],  8)
        HHH(&ddd, eee, &aaa, bbb, ccc, X[14],  6)
        HHH(&ccc, ddd, &eee, aaa, bbb, X[ 6],  6)
        HHH(&bbb, ccc, &ddd, eee, aaa, X[ 9], 14)
        HHH(&aaa, bbb, &ccc, ddd, eee, X[11], 12)
        HHH(&eee, aaa, &bbb, ccc, ddd, X[ 8], 13)
        HHH(&ddd, eee, &aaa, bbb, ccc, X[12],  5)
        HHH(&ccc, ddd, &eee, aaa, bbb, X[ 2], 14)
        HHH(&bbb, ccc, &ddd, eee, aaa, X[10], 13)
        HHH(&aaa, bbb, &ccc, ddd, eee, X[ 0], 13)
        HHH(&eee, aaa, &bbb, ccc, ddd, X[ 4],  7)
        HHH(&ddd, eee, &aaa, bbb, ccc, X[13],  5)

        /* parallel round 4 */
        GGG(&ccc, ddd, &eee, aaa, bbb, X[ 8], 15)
        GGG(&bbb, ccc, &ddd, eee, aaa, X[ 6],  5)
        GGG(&aaa, bbb, &ccc, ddd, eee, X[ 4],  8)
        GGG(&eee, aaa, &bbb, ccc, ddd, X[ 1], 11)
        GGG(&ddd, eee, &aaa, bbb, ccc, X[ 3], 14)
        GGG(&ccc, ddd, &eee, aaa, bbb, X[11], 14)
        GGG(&bbb, ccc, &ddd, eee, aaa, X[15],  6)
        GGG(&aaa, bbb, &ccc, ddd, eee, X[ 0], 14)
        GGG(&eee, aaa, &bbb, ccc, ddd, X[ 5],  6)
        GGG(&ddd, eee, &aaa, bbb, ccc, X[12],  9)
        GGG(&ccc, ddd, &eee, aaa, bbb, X[ 2], 12)
        GGG(&bbb, ccc, &ddd, eee, aaa, X[13],  9)
        GGG(&aaa, bbb, &ccc, ddd, eee, X[ 9], 12)
        GGG(&eee, aaa, &bbb, ccc, ddd, X[ 7],  5)
        GGG(&ddd, eee, &aaa, bbb, ccc, X[10], 15)
        GGG(&ccc, ddd, &eee, aaa, bbb, X[14],  8)

        /* parallel round 5 */
        FFF(&bbb, ccc, &ddd, eee, aaa, X[12] ,  8)
        FFF(&aaa, bbb, &ccc, ddd, eee, X[15] ,  5)
        FFF(&eee, aaa, &bbb, ccc, ddd, X[10] , 12)
        FFF(&ddd, eee, &aaa, bbb, ccc, X[ 4] ,  9)
        FFF(&ccc, ddd, &eee, aaa, bbb, X[ 1] , 12)
        FFF(&bbb, ccc, &ddd, eee, aaa, X[ 5] ,  5)
        FFF(&aaa, bbb, &ccc, ddd, eee, X[ 8] , 14)
        FFF(&eee, aaa, &bbb, ccc, ddd, X[ 7] ,  6)
        FFF(&ddd, eee, &aaa, bbb, ccc, X[ 6] ,  8)
        FFF(&ccc, ddd, &eee, aaa, bbb, X[ 2] , 13)
        FFF(&bbb, ccc, &ddd, eee, aaa, X[13] ,  6)
        FFF(&aaa, bbb, &ccc, ddd, eee, X[14] ,  5)
        FFF(&eee, aaa, &bbb, ccc, ddd, X[ 0] , 15)
        FFF(&ddd, eee, &aaa, bbb, ccc, X[ 3] , 13)
        FFF(&ccc, ddd, &eee, aaa, bbb, X[ 9] , 11)
        FFF(&bbb, ccc, &ddd, eee, aaa, X[11] , 11)

        /* combine results */
        MDbuf = (MDbuf.1 &+ cc &+ ddd,
                 MDbuf.2 &+ dd &+ eee,
                 MDbuf.3 &+ ee &+ aaa,
                 MDbuf.4 &+ aa &+ bbb,
                 MDbuf.0 &+ bb &+ ccc)
    }

    public mutating func update(data: Data) {
        var X = [UInt32](repeating: 0, count: 16)
        var pos = data.startIndex
        var length = data.count

        // Process remaining bytes from last call:
        if buffer.count > 0 && buffer.count + length >= 64 {
            let amount = 64 - buffer.count
            buffer.append(data[..<amount])
            X.withUnsafeMutableBytes {
                _ = buffer.copyBytes(to: $0)
            }
            compress(X)
            pos += amount
            length -= amount
        }

        // Process 64 byte chunks:
        while length >= 64 {
            X.withUnsafeMutableBytes {
                _ = data[pos..<pos+64].copyBytes(to: $0)
            }
            compress(X)
            pos += 64
            length -= 64
        }

        // Save remaining unprocessed bytes:
        buffer = data[pos...]
        count += Int64(data.count)
    }

    public mutating func finalize() -> Data {
        var X = [UInt32](repeating: 0, count: 16)
        /* append the bit m_n == 1 */
        buffer.append(0x80)
        X.withUnsafeMutableBytes {
            _ = buffer.copyBytes(to: $0)
        }

        if (count & 63) > 55 {
            /* length goes to next block */
            compress(X)
            X = [UInt32](repeating: 0, count: 16)
        }

        /* append length in bits */
        let lswlen = UInt32(truncatingIfNeeded: count)
        let mswlen = UInt32(UInt64(count) >> 32)
        X[14] = lswlen << 3
        X[15] = (lswlen >> 29) | (mswlen << 3)
        compress(X)

        buffer = Data()
        let result = [MDbuf.0, MDbuf.1, MDbuf.2, MDbuf.3, MDbuf.4]
        return result.withUnsafeBytes { Data($0) }
    }
}
public extension RIPEMD160 {
     static func hash(message: Data) -> Data {
        var md = RIPEMD160()
        md.update(data: message)
        return md.finalize()
    }
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class Input {
    let trxID: String
    let index: UInt32
    let balance: UInt64
    let address: String
    
    /// Create an input funding transaction
    /// - Parameters:
    ///    - trxID: ID of the funding transaction
    ///    - index: unspent index to use
    ///    - balance: amount unspent
    ///    - address: sender's address
    init(trxID: String, balance: UInt64, address: String, index: UInt32) {
        self.trxID = trxID
        self.balance = balance
        self.index = index
        self.address = address
    }
}

class Transaction {
    let pubKey: String
    let privateKey: String
    let input: Input
    let version: UInt32 = 0x01
    let numInputs: UInt8 = 0x01
    let sequence: UInt32 = 0xffffffff
    let numOutputs: UInt8 = 0x02
    let value: UInt64
    let toAddress: String
    let locktime: UInt32 = 0x0
    let sigHashCode: UInt32 = 0x01
    let minerFee: UInt64
    
    let OP_DUP = 0x76
    let OP_HASH160 = 0xa9
    let OP_EQUALVERIFY = 0x88
    let OP_CHECKSIG = 0xac
    
    let SEGWIT_MARKER = 0x00
    let SEGWIT_FLAG = 0x01
    
    /// Create a P2WPKH transaction
    /// - Parameters:
    ///    - input: instance of Input class
    ///    - value: amount to be sent in satoshi
    ///    - toAddress: recieving address
    ///    - pubKey: compressed public key of the sender (starts with 0x03 or 0x02)
    ///    - privateKey: private key of the sender (hex version not WIF)
    ///    - minerFee: miner fees in satoshi
    init(input: Input, value: UInt64, toAddress: String, pubKey:String, privateKey: String, minerFee: UInt64) {
        self.input = input
        self.minerFee = UInt64(minerFee)
        self.value = UInt64(value)
        self.toAddress = toAddress
        self.pubKey = pubKey
        self.privateKey = privateKey
    }
    
    func reverseByteEndianOrder(hexString: String) -> String {
        /// reverse little endian hex string to big endian and vice-versa
        var i = 2
        var final = ""
            
        while i <= hexString.count {
            let _startIdx = hexString.index(hexString.endIndex, offsetBy: -i)
            let _endIdx = hexString.index(hexString.endIndex, offsetBy: -i + 2)
            final += hexString[_startIdx..<_endIdx]
            i += 2
        }

        return final
    }
    
    func createScriptPubKey(btcAddress: String) -> String {
        /// Segwit format: 00 <LEN> <PUB_KEY_HASH>
        let addrCoder = SegwitAddrCoder()
        let decoded = try? addrCoder.decode(hrp: "tb", addr: btcAddress)
        let pubHashKey = decoded!.1.toHexString()
        
        return "00" + String(format: "%02x", pubHashKey.count / 2) + pubHashKey
    }
    
    func getPubKeyHash(pubKey: String) -> String {
        /// pubKeyHash = RIPEMD160 ( SHA256 ( pubKey ) )
        let bytes = Array<UInt8>(hex: pubKey)
        let sha256 = bytes.sha256()
        
        let hash = RIPEMD160.hash(message: Data(sha256))
        
        return  hash.map { String(format: "%02hhx", $0) }.joined()
    }
    
    func createScriptCode(pubKeyHash: String) -> String {
        /// OP_DUP OP_HASH160 <BYTES_TO_PUSH> <PUB_KEY_HASH> OP_EQUALVERIFY OP_CHECKSIG
        let script = String(format:"%02x", OP_DUP) + String(format:"%02x", OP_HASH160) + String(format:"%02x", pubKeyHash.count / 2) + pubKeyHash + String(format:"%02x", OP_EQUALVERIFY) + String(format:"%02x", OP_CHECKSIG)
        return String(format: "%02x", script.count / 2) + script
    }
   
    func createSegwitMessageTemplate() -> String {
        /// Format:
        /// Double SHA256 of the serialization
        /// 1.  nVersion of the transaction (4-byte little endian)
        /// 2.  hashPrevouts (32-byte hash)
        /// 3.  hashSequence (32-byte hash)
        /// 4.  outpoint (32-byte hash + 4-byte little endian)
        /// 5.  scriptCode of the input (serialized as scripts inside CTxOuts)
        /// 6.  value of the output spent by this input (8-byte little endian)
        /// 7.  nSequence of the input (4-byte little endian)
        /// 8.  hashOutputs (32-byte hash)
        /// 9.  nLocktime of the transaction (4-byte little endian)
        /// 10. sighash type of the signature (4-byte little endian)

        let hashPrevOuts = Array<UInt8>(hex: (self.reverseByteEndianOrder(hexString: self.input.trxID) + String(format: "%08x", self.input.index.bigEndian))).sha256().sha256()
        let hashSequence = Array<UInt8>(hex: String(format: "%08x", self.sequence)).sha256().sha256()
        let outpoint = self.reverseByteEndianOrder(hexString: self.input.trxID) + String(format: "%08x", self.input.index.bigEndian)
        let scriptCode = self.createScriptCode(pubKeyHash: self.getPubKeyHash(pubKey: self.pubKey))
        
        let hashOutputs = Array<UInt8>(hex: (self.createPayeeOutput() + self.createRefundOutput())).sha256().sha256()
        
        return String(format: "%08x", self.version.bigEndian) +
            hashPrevOuts.toHexString() +
            hashSequence.toHexString() +
            outpoint +
            scriptCode +
            String(format: "%llx", self.input.balance.bigEndian) +
            String(format: "%08x", self.sequence) +
            hashOutputs.toHexString() +
            String(format: "%08x", self.locktime.bigEndian) +
            String(format: "%08x", self.sigHashCode.bigEndian)
    }
    
    func createRefundOutput() -> String {
        let refund = self.input.balance - self.minerFee - self.value

        let refundScriptPubKey = self.createScriptPubKey(btcAddress: self.input.address)
        let hashOutputRefund = String(format: "%llx", refund.bigEndian) + String(format: "%02x", refundScriptPubKey.count / 2) + refundScriptPubKey
        return hashOutputRefund
    }
    
    func createPayeeOutput() -> String {
        let payeeScriptPubKey = self.createScriptPubKey(btcAddress: self.toAddress)
        let hashOutputPayee = String(format: "%llx", self.value.bigEndian) + String(format: "%02x", payeeScriptPubKey.count / 2) + payeeScriptPubKey
        return hashOutputPayee
    }

    
    func sign() -> String {
        /// Sign data using ECDSA using secp256k1 curve

        let template = self.createSegwitMessageTemplate()
       
        let privateKeyBytes = try! self.privateKey.byteArray()
        let pk = try! secp256k1.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
        
        /// ecdsa.signature() requires a SHA256 Digest type as argument, hence we can't use data.sha256()
        /// we have to use SHA256.hash()
        let hash = SHA256.hash(data: Array<UInt8>(hex: template))
        let doubleHash = SHA256.hash(data: Array<UInt8>(hex: hash.compactMap { String(format: "%02x", $0) }.joined()))
        let signature = try! pk.ecdsa.signature(for: doubleHash)
        let der = try! signature.derRepresentation
        
        return der.toHexString() + String(format: "%02x", self.sigHashCode) /// Append sig hash code with DER signature
    }
    
    func createWitness() -> String {
        /// <NUM_ITEMS> <SIGNATURE> + <PUB_KEY>
        let _sign = self.sign()
        return String(format: "%02x", 0x02) +
            String(format: "%02x", _sign.count / 2) +
            _sign +
            String(format: "%02x", self.pubKey.count / 2) +
            self.pubKey
    }
    
    func createInput() -> String {
        let input = self.reverseByteEndianOrder(hexString: self.input.trxID) +
            String(format:"%08x", self.input.index.bigEndian) +
            "00" + /// "0x00" is required for segwit trx
            String(format:"%08x", self.sequence)
        
        return input
    }
    
    func createTrxID() -> String {
        let format = String(format:"%08x", self.version.bigEndian) +
            String(format:"%02x", self.numInputs.bigEndian) +
            self.createInput() +
            String(format:"%02x", self.numOutputs.bigEndian) +
            self.createPayeeOutput() +
            self.createRefundOutput() +
            String(format:"%08x", self.locktime.bigEndian)
        
        let doubleHash = Array<UInt8>(hex: format).sha256().sha256().toHexString()
        
        return self.reverseByteEndianOrder(hexString: doubleHash)
    }
    
    func create() -> (String, String) {
        let hex = String(format:"%08x", self.version.bigEndian) +
            String(format: "%02x", SEGWIT_MARKER) +
            String(format: "%02x", SEGWIT_FLAG) +
            
            /// inputs
            String(format:"%02x", self.numInputs.bigEndian) +
            self.createInput() +

            /// outputs
            String(format:"%02x", self.numOutputs.bigEndian) +
            self.createPayeeOutput() +
            self.createRefundOutput() +
        
            /// witness
            self.createWitness() +
            String(format:"%08x", self.locktime.bigEndian)
        
        return (self.createTrxID(), hex)
        
    }
}

struct ContentView: View {
    @State var toAddress: String = ""
    @State var minerFee: String = ""
    @State var transactionHex: String = "-"
    @State var transactionID: String = "-"
    @State var showingAlert = false
    @State var value = ""

    /// hard coded input constants
    let INPUT_TRX_ID = "d5832b04d8b3ffd871ef6da739de56f5d8408b6a161d61a19974106f40ef382d"
    let INPUT_BALANCE = UInt64(100000)
    let INPUT_INDEX = UInt32(0x0)
    let PUB_KEY = "038afc1c853d42d06312fc7585aadf168ffd990f23c935c81b3be7e77f17f979ce"
    let PRIVATE_KEY = "aea44f851ff6695f0027e63031cc9fd34507f1c82e55c8a19c8b1182ad1c7332"
    let INPUT_ADDRESS = "tb1qqg7h3z0pjmu9y55mszlyypqeek376ddlzphp9k"
    
    
    var body: some View {
        ScrollView {
            
            VStack {
                Image("btc")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 100)
            }.padding()
            
            
            
            HStack {
                Text("funding input tx")
                    .fontWeight(.bold)
                    .frame(width: 100, alignment: .leading)
                    
                Text(INPUT_TRX_ID).font(.system(size: 14, design: .monospaced))
                
            }
            
            HStack {
                Text("to address")
                    .fontWeight(.bold)
                    .frame(width: 100, alignment: .leading)
                
                TextField("bech32 segwit (tb1..)", text: $toAddress)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .font(.system(size: 14, design: .monospaced))
                    
            }
            
            HStack {
                Text("value")
                    .fontWeight(.bold)
                    .frame(width: 100, alignment: .leading)
                
                TextField("in satoshi", text: $value)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .font(.system(size: 14, design: .monospaced))
                    
            }
            
            HStack {
                Text("miner fee")
                    .fontWeight(.bold)
                    .frame(width: 100, alignment: .leading)
                
                TextField("in satoshi", text: $minerFee)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .font(.system(size: 14, design: .monospaced))
                    
            }
            
            
            Button(action: {
                if (isValidAddress(addr: self.toAddress)) {
                    createTransaction()
                }
            }, label: {
                Text("Create transaction")
                    .foregroundColor(.white)
                    .padding()
                    .frame(maxWidth: .infinity)
                    
            })
            .background(Color.black.cornerRadius(10))
            .alert("supported format: testnet bech32 addresses (starts with tb1)", isPresented: $showingAlert) {
                    Button("OK", role: .cancel) { }
            }
            
            Divider().padding(.top, 20).padding(.bottom, 20)
            
            HStack {
                Text("trx hex")
                    .bold()
                    .frame(width: 100, alignment: .leading)
                    
                Text(transactionHex)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .font(.system(size: 14, design: .monospaced))
            }.textSelection(.enabled)
    
            HStack {
                Text("trx id")
                    .bold()
                    .frame(width: 100, alignment: .leading)
                
                Text(transactionID)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .font(.system(size: 14, design: .monospaced))
            }.textSelection(.enabled).padding(.top, 5)
            
            
        }.padding()
    }
    
    func isValidAddress(addr: String) -> Bool {
        if (addr.hasPrefix("tb1") && addr.count == 42) {
            /// only segwit bech32 test addresses are supported
            return true
        }
        showingAlert = true
        
        return false
    }
    
    func createTransaction() {
        let input = Input(
            trxID: INPUT_TRX_ID,
            balance: INPUT_BALANCE,
            address: INPUT_ADDRESS,
            index: INPUT_INDEX
        )


        let trx = Transaction(
            input: input,
            value: UInt64(self.value)!,
            toAddress: self.toAddress,
            pubKey: PUB_KEY,
            privateKey: PRIVATE_KEY,
            minerFee: UInt64(self.minerFee)!
        )
                
        let newTrx = trx.create()
        transactionID = newTrx.0
        transactionHex = newTrx.1
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
