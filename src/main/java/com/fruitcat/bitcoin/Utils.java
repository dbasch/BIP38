/**
 *
 * Copyright 2014 Diego Basch
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.fruitcat.bitcoin;

import com.google.bitcoin.core.Base58;
import org.bouncycastle.math.ec.ECPoint;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Utils {

    /**
     * Compress a point.
     * @param uncompressed
     * @return
     */
    public static ECPoint compressPoint(ECPoint uncompressed) {
        return new ECPoint.Fp(uncompressed.getCurve(), uncompressed.getX(), uncompressed.getY(), true);
    }

    /**
     * Performs a double SHA-256 hash on a byte array (or a portion of it).
     * @param data
     * @param off
     * @param len
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static byte[] doubleHash(byte [] data, int off, int len) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(data, off, len);
        return md.digest(md.digest());
    }

    /**
     * Performs a RIPEMD-160 hash of a SHA-256 hash of a byte array.
     * @param data
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static byte[] sha256ripe160(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest r = MessageDigest.getInstance("RIPEMD160");
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        return r.digest(sha.digest(data));
    }

    //for debugging
    protected static void pb(byte [] x) {
        for (byte b : x) {
            int l = b >= 0 ? b : 256 + b;
            System.out.print(l + " ");
        }
        System.out.println();
    }

    /**
     * Appends a Bitcoin-style checksum to a byte array and encodes the result as Base58.
     * @param b a byte array
     * @return the encoded concatenation of the byte array and its checksum
     * @throws NoSuchAlgorithmException
     */

    public static String base58Check(byte [] b) throws NoSuchAlgorithmException {
        byte[] r = new byte[b.length + 4];
        System.arraycopy(b, 0, r, 0, b.length);
        System.arraycopy(doubleHash(b, 0, b.length), 0, r, b.length, 4);
        return Base58.encode(r);
    }
}
