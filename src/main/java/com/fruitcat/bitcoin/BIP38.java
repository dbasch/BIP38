/**
 * Implementation of BIP38 encryption / decryption / key-address generation
 * Based on https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
 * 
 * Copyright 2014 Diego Basch
 * Tips much appreciated: 1EmwBbfgH7BPMoCpcFzyzgAN9Ya7jm8L1Z :)
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

import com.google.bitcoin.core.*;
import com.google.bitcoin.params.MainNetParams;
import com.lambdaworks.crypto.SCrypt;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.util.Arrays;

public class BIP38 {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private static final X9ECParameters CURVE = SECNamedCurves.getByName("secp256k1");

    /**
     * Generates an encrypted key with EC multiplication.
     * Only uncompressed format for now.
     * if lot is less than 0, lot and sequence are ignored.j
     * @param password
     * @return
     * @throws UnsupportedEncodingException
     * @throws GeneralSecurityException
     * @throws AddressFormatException
     */
    public static String encryptEC(String password, int lot, int sequence) throws UnsupportedEncodingException, GeneralSecurityException, AddressFormatException {

        byte[] intermediate = Base58.decode(intermediatePassphrase(password, lot, sequence));

        byte flagByte = (lot > 0) ? (byte) 4 : (byte) 0; //uncompressed
        byte[] ownerEntropy = new byte[8];
        byte[] passPoint = new byte[33];
        System.arraycopy(intermediate, 8, ownerEntropy, 0, 8);
        System.arraycopy(intermediate, 16, passPoint, 0, 33);

        byte[] seedB = new byte[24];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(seedB);
        byte[] factorB = Utils.doubleHash(seedB, 0, 24);
        ECPoint p = CURVE.getCurve().decodePoint(passPoint);
        ECPoint pk = p.multiply(new BigInteger(1, factorB));
        byte[] generatedAddress = Utils.sha256ripe160(pk.getEncoded());
        byte[] add = new Address(MainNetParams.get(), generatedAddress).toString().getBytes();
        byte[] addressHash = Utils.doubleHash(add, 0, add.length);

        byte[] salt = new byte[12];
        System.arraycopy(addressHash, 0, salt, 0, 4);
        System.arraycopy(ownerEntropy, 0, salt, 4, 8);
        byte[] secondKey = SCrypt.scrypt(passPoint, salt, 1024, 1, 1, 64);
        byte[] derivedHalf1 = Arrays.copyOfRange(secondKey, 0, 32);
        byte[] derivedHalf2 = Arrays.copyOfRange(secondKey, 32, 64);

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");

        byte[] m1 = new byte[16];
        byte[] m2 = new byte[16];
        for (int i = 0; i < 16; i++) {
            m1[i] = (byte) (seedB[i] ^ derivedHalf1[i]);
        }
        Key aesKey = new SecretKeySpec(derivedHalf2, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedPart1 = cipher.doFinal(m1);
        System.arraycopy(encryptedPart1, 8, m2, 0, 8);
        System.arraycopy(seedB, 16, m2, 8, 8);

        for (int i = 0; i < 16; i++) {
            m2[i] = (byte) (m2[i] ^ derivedHalf1[16 + i]);
        }

        byte[] encryptedPart2 = cipher.doFinal(m2);
        byte[] encryptedPrivateKey = new byte[43];
        encryptedPrivateKey[0] = 0x01;
        encryptedPrivateKey[1] = 0x43;
        encryptedPrivateKey[2] = flagByte;
        System.arraycopy(addressHash, 0, encryptedPrivateKey, 3, 4);
        System.arraycopy(ownerEntropy, 0, encryptedPrivateKey, 7, 8);
        System.arraycopy(encryptedPart1, 0, encryptedPrivateKey, 15, 8);
        System.arraycopy(encryptedPart2, 0, encryptedPrivateKey, 23, 16);
        System.arraycopy(addressHash, 0, encryptedPrivateKey, 39, 4);
        System.arraycopy(Utils.doubleHash(encryptedPrivateKey, 0, 39), 0, encryptedPrivateKey, 39, 4);

        return Base58.encode(encryptedPrivateKey);
    }

    /**
     * Generates the intermediate passphrase string as specified by BIP-0038.
     * If lot is a negative number, lot and sequence are not used.
     * @param password
     * @param lot
     * @param sequence
     * @return the passphrase
     * @throws UnsupportedEncodingException
     * @throws GeneralSecurityException
     */
    public static String intermediatePassphrase(String password, int lot, int sequence)
            throws UnsupportedEncodingException, GeneralSecurityException {

        SecureRandom sr = new SecureRandom();
        byte[] ownerEntropy;
        byte[] ownerSalt;
        byte[] passPoint;
        byte[] preFactor;
        byte[] result = new byte[53];
        byte[] magicBytes = { (byte) 0x2c, (byte) (0xe9), (byte) 0xb3, (byte) 0xe1, (byte) 0xff, (byte) 0x39, (byte) 0xe2, (byte) 0x51 };
        byte[] passFactor;

        if (lot >= 0) {
            ownerEntropy = new byte[8];
            ownerSalt = new byte[4];
            sr.nextBytes(ownerSalt);
            ByteBuffer b = ByteBuffer.allocate(4);
            b.order(ByteOrder.BIG_ENDIAN); // redundant in Java because it's the default
            b.putInt(4096 * lot + sequence);
            byte[] ls = b.array();
            System.arraycopy(ownerSalt, 0, ownerEntropy, 0, 4);
            System.arraycopy(ls, 0, ownerEntropy, 4, 4);
            preFactor = SCrypt.scrypt(password.getBytes("UTF8"), ownerSalt, 16384, 8, 8, 32);
            byte[] tmp = new byte[40];
            System.arraycopy(preFactor, 0, tmp, 0, 32);
            System.arraycopy(ownerEntropy, 0, tmp, 32, 8);
            passFactor = Utils.doubleHash(tmp, 0, 40);

        } else {
            magicBytes[7] = (byte) 0x53;
            ownerSalt = new byte[8];
            sr.nextBytes(ownerSalt);
            ownerEntropy = ownerSalt;
            passFactor = SCrypt.scrypt(password.getBytes("UTF8"), ownerSalt, 16384, 8, 8, 32);
        }

        ECPoint g = CURVE.getG();
        ECPoint p = Utils.compressPoint(g.multiply(new BigInteger(1, passFactor)));
        passPoint = p.getEncoded();
        System.arraycopy(magicBytes, 0, result, 0, 8);
        System.arraycopy(ownerEntropy, 0, result, 8, 8);
        System.arraycopy(passPoint, 0, result, 16, 33);
        byte[] checksum = Arrays.copyOfRange(Utils.doubleHash(result, 0, 49), 0, 4);

        System.arraycopy(checksum, 0, result, 49, 4);
        return Base58.encode(result);
    }

    /**
     * Decrypts an encrypted key.
     * @param password
     * @param encryptedKey
     * @return decrypted key
     * @throws AddressFormatException
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */
    public static String decrypt(String password, String encryptedKey) throws
            AddressFormatException, GeneralSecurityException, UnsupportedEncodingException {
        byte[] encryptedKeyBytes = Base58.decode(encryptedKey);
        int l = encryptedKeyBytes.length;
        String result;
        switch (l) {
            case 43: result = decryptEC(password, encryptedKeyBytes);
                break;
            case 53: result = decryptNoEC(password, encryptedKeyBytes);
                break;
            default: throw new RuntimeException("Invalid Key");
        }
        return result;
    }

    /**
     * Decrypts a key encrypted with EC multiplication
     * @param password
     * @param encryptedKey
     * @return decrypted key
     * @throws UnsupportedEncodingException
     * @throws GeneralSecurityException
     */
    public static String decryptEC(String password, byte[] encryptedKey) throws UnsupportedEncodingException, GeneralSecurityException {

        byte flagByte = encryptedKey[2];
        byte[] passFactor;
        byte[] ownerSalt = Arrays.copyOfRange(encryptedKey, 7, 15 - (flagByte & 4));
        if ((flagByte & 4) == 0) {
            passFactor = SCrypt.scrypt(password.getBytes("UTF8"), ownerSalt, 16384, 8, 8, 32);
        }
        else {
            byte[] preFactor = SCrypt.scrypt(password.getBytes("UTF8"), ownerSalt, 16384, 8, 8, 32);
            byte[] ownerEntropy = new byte[8];
            System.arraycopy(encryptedKey, 7, ownerEntropy, 0, 8);
            byte[] tmp = new byte[40];
            System.arraycopy(preFactor, 0, tmp, 0, 32);
            System.arraycopy(ownerEntropy, 0, tmp, 32, 8);
            passFactor = Utils.doubleHash(tmp, 0, 40);

        }
        byte[] addressHash = Arrays.copyOfRange(encryptedKey, 3, 7);
        ECPoint g = CURVE.getG();
        ECPoint p = Utils.compressPoint(g.multiply(new BigInteger(1, passFactor)));
        byte[] passPoint = p.getEncoded();
        byte[] salt = new byte[12];
        byte[] encryptedPart2 = Arrays.copyOfRange(encryptedKey, 23, 39);
        System.arraycopy(addressHash, 0, salt, 0, 4);
        System.arraycopy(encryptedKey, 7, salt, 4, 8);

        byte[] secondKey = SCrypt.scrypt(passPoint, salt, 1024, 1, 1, 64);
        Cipher cipher = Cipher.getInstance ("AES/ECB/NoPadding");
        byte[] derivedHalf1 = Arrays.copyOfRange(secondKey, 0, 32);
        byte[] derivedHalf2 = Arrays.copyOfRange(secondKey, 32, 64);
        SecretKeySpec aesKey = new SecretKeySpec(derivedHalf2, "AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] m2 = cipher.doFinal(encryptedPart2);

        byte[] encryptedPart1 = new byte[16];
        byte[] seedB = new byte[24];

        for (int i = 0; i < 16; i++) {
            m2[i] = (byte) (m2[i] ^ derivedHalf1[16 + i]);
        }

        System.arraycopy(m2, 0, encryptedPart1, 8, 8);
        System.arraycopy(encryptedKey, 15, encryptedPart1, 0, 8);

        byte[] m1 = cipher.doFinal(encryptedPart1);

        for (int i = 0; i < 16; i++) {
            seedB[i] = (byte) (m1[i] ^ derivedHalf1[i]);
        }

        System.arraycopy(m2, 8, seedB, 16, 8);
        byte[] factorB = Utils.doubleHash(seedB, 0, 24);
        BigInteger n = CURVE.getN();
        BigInteger pk = new BigInteger(1, passFactor).multiply(new BigInteger(1, factorB)).remainder(n);

        ECKey privKey = new ECKey(pk, null);
        return privKey.getPrivateKeyEncoded(MainNetParams.get()).toString();
    }

    /**
     * Encrypts a key without using EC multiplication. - UNTESTED, probably doesn't work.
     * @param encodedPrivateKey
     * @param password
     * @param compressed
     * @param params
     * @return
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     * @throws AddressFormatException
     */
    public static String encryptNoEC(String encodedPrivateKey, String password, boolean compressed, NetworkParameters params)
            throws GeneralSecurityException, UnsupportedEncodingException, AddressFormatException {

        byte[] keyBytes = Base58.decode(encodedPrivateKey);
        ECKey key = new ECKey(keyBytes, null);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] d1 = digest.digest(key.toAddress(params).getHash160());
        byte[] hash = digest.digest(d1);
        byte[] addressHash = Arrays.copyOfRange(hash, 0, 4);
        byte[] scryptKey = SCrypt.scrypt(password.getBytes("UTF8"), addressHash, 16384, 8, 8, 64);
        byte[] derivedHalf1 = Arrays.copyOfRange(scryptKey, 0, 32);
        byte[] derivedHalf2 = Arrays.copyOfRange(scryptKey, 32, 64);

        byte[] k1 = new byte[16];
        byte[] k2 = new byte[16];
        for (int i = 0; i < 16; i++) {
            k1[i] = (byte) (keyBytes[i] ^ derivedHalf1[i]);
            k2[i] = (byte) (keyBytes[i+16] ^ derivedHalf1[i+16]);
        }
        Cipher cipher = Cipher.getInstance ("AES/ECB/NoPadding", "BC");
        Key aesKey1 = new SecretKeySpec(k1, "AES");
        Key aesKey2 = new SecretKeySpec(k2, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, aesKey1);
        byte[] encryptedHalf1 = cipher.doFinal(derivedHalf2);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey2);
        byte[] encryptedHalf2 = cipher.doFinal(derivedHalf2);

        byte[] encryptedPrivateKey = new byte[43];
        encryptedPrivateKey[0] = 0x01;
        encryptedPrivateKey[1] = 0x42;
        encryptedPrivateKey[2] = (byte) (compressed ? 0xe0 : 0xc0);
        System.arraycopy(addressHash, 0, encryptedPrivateKey, 3, 4);
        System.arraycopy(encryptedHalf1, 0, encryptedPrivateKey, 7, 16);
        System.arraycopy(encryptedHalf2, 0, encryptedPrivateKey, 23, 16);
        System.arraycopy(addressHash, 0, encryptedPrivateKey, 39, 4);

        return Base58.encode(encryptedPrivateKey);
    }


    public static String decryptNoEC(String password, byte[] encryptedKey) {
        throw new RuntimeException("not implemented yet");
    }

    // generate a key, decrypt it, print the decrypted key and the address.
    public static void main(String args[]) throws Exception {
        String encryptedKey = encryptEC("hello", 1, 1);
        System.out.println(encryptedKey);
        String key = decrypt("hello", encryptedKey);
        DumpedPrivateKey dk = new DumpedPrivateKey(MainNetParams.get(), key);
        ECKey k = dk.getKey();
        String add = k.toAddress(MainNetParams.get()).toString();
        System.out.println("Key: " + key + "\nAddress:" + add);
    }
}