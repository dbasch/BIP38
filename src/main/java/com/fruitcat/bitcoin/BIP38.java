/**
 * Implementation of BIP38 encryption / decryption / key-address generation
 * Based on https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
 *
 * Tips much appreciated: 1EmwBbfgH7BPMoCpcFzyzgAN9Ya7jm8L1Z :)
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

import com.google.bitcoin.core.*;
import com.google.bitcoin.params.MainNetParams;
import com.lambdaworks.crypto.SCrypt;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

public class BIP38 {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private static final X9ECParameters CURVE = SECNamedCurves.getByName("secp256k1");

    /**
     * Generates an encrypted key with EC multiplication.
     * Only uncompressed format for now.
     *
     * @param password
     * @return
     * @throws UnsupportedEncodingException
     * @throws GeneralSecurityException
     * @throws AddressFormatException
     */
    public static String generateEncryptedKey(String password) throws UnsupportedEncodingException, GeneralSecurityException, AddressFormatException {

        byte[] intermediate = Arrays.copyOfRange(Base58.decode(intermediatePassphrase(password, -1, -1)), 0, 53);
        return encryptedKeyFromIntermediate(intermediate).key;
    }

    /**
     * Generates a private key from an intermediate passphrase.
     *
     * @param intermediate
     * @return
     * @throws GeneralSecurityException
     */
    public static GeneratedKey encryptedKeyFromIntermediate(byte[] intermediate) throws GeneralSecurityException {

        byte flagByte = (0x51 == intermediate[7]) ? (byte) 4 : (byte) 0; //uncompressed
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

        byte[] salt = Utils.concat(addressHash, ownerEntropy);
        byte[] secondKey = SCrypt.scrypt(passPoint, salt, 1024, 1, 1, 64);
        byte[] derivedHalf1 = Arrays.copyOfRange(secondKey, 0, 32);
        byte[] derivedHalf2 = Arrays.copyOfRange(secondKey, 32, 64);

        byte[] m1 = new byte[16];
        byte[] m2 = new byte[16];
        for (int i = 0; i < 16; i++) {
            m1[i] = (byte) (seedB[i] ^ derivedHalf1[i]);

        }

        byte[] encryptedPart1 = Utils.AESEncrypt(m1, derivedHalf2);
        System.arraycopy(encryptedPart1, 8, m2, 0, 8);
        System.arraycopy(seedB, 16, m2, 8, 8);
        for (int i = 0 ; i < 16; i ++) {
            m2[i] = (byte) (m2[i] ^ derivedHalf1[16 + i]);
        }

        byte[] encryptedPart2 = Utils.AESEncrypt(m2, derivedHalf2);
        byte[] header = { 0x01, 0x43, flagByte};

        byte[] encryptedPrivateKey = Utils.concat(header, addressHash, ownerEntropy,
                Arrays.copyOfRange(encryptedPart1, 0, 8), encryptedPart2);

        String key = Utils.base58Check(encryptedPrivateKey);
        String confirmationCode = confirmation(flagByte, addressHash, ownerEntropy, factorB, derivedHalf1, derivedHalf2);
        return new GeneratedKey(key, confirmationCode);
    }

    private static String confirmation(byte flagByte, byte[] addressHash, byte [] ownerEntropy, byte[] factorB, byte[] derivedHalf1, byte[] derivedHalf2)
            throws GeneralSecurityException {
        byte[] pointB = CURVE.getG().multiply(new BigInteger(1, factorB)).getEncoded();
        byte pointBPrefix = (byte) (pointB[0] ^ (derivedHalf2[31] & 1));
        byte[] m1 = new byte[16];
        byte[] m2 = new byte[16];
        for (int i = 0 ; i < 16; i ++) {
            m1[i] = (byte) (pointB[i] ^ derivedHalf1[i]);
            m2[i] = (byte) (pointB[16 + i] ^ derivedHalf1[16 + i]);
        }
        byte[] pointBx1 = Utils.AESEncrypt(m1, derivedHalf2);
        byte[] pointBx2 = Utils.AESEncrypt(m2, derivedHalf2);
        byte[] encryptedPointB = Utils.concat(new byte[] { pointBPrefix }, pointBx1, pointBx2);
        byte[] header = {(byte) 0x64, (byte) 0x3B, (byte) 0xF6, (byte) 0xA8, (byte) 0x9A, flagByte};
        byte[] result = Utils.concat(header, addressHash, ownerEntropy, encryptedPointB);

        return Utils.base58Check(result);
    }

    public boolean verify(String passphrase, String confirmationCode) {
          return true;
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
            byte[] tmp = Utils.concat(preFactor, ownerEntropy);
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
        byte[] result = Utils.concat(magicBytes, ownerEntropy, passPoint);

        return Utils.base58Check(result);
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
        String result;
        byte ec = encryptedKeyBytes[1];
        switch (ec) {
            case 0x43: result = decryptEC(password, encryptedKeyBytes);
                break;
            case 0x42: result = decryptNoEC(password, encryptedKeyBytes);
                break;
            default: throw new RuntimeException("Invalid key - second byte is: " + ec);
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
        byte[] derivedHalf1 = Arrays.copyOfRange(secondKey, 0, 32);
        byte[] derivedHalf2 = Arrays.copyOfRange(secondKey, 32, 64);
        byte[] m2 = Utils.AESDecrypt(encryptedPart2, derivedHalf2);

        byte[] encryptedPart1 = new byte[16];
        System.arraycopy(encryptedKey, 15, encryptedPart1, 0, 8);

        byte[] seedB = new byte[24];

        for (int i = 0; i < 16; i++) {
            m2[i] = (byte) (m2[i] ^ derivedHalf1[16 + i]);
        }
        System.arraycopy(m2, 0, encryptedPart1, 8, 8);

        byte[] m1 = Utils.AESDecrypt(encryptedPart1, derivedHalf2);

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
     * Encrypts a key without using EC multiplication.
     * @param encodedPrivateKey
     * @param password
     * @param isCompressed
     * @return
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     * @throws AddressFormatException
     */
    public static String encryptNoEC(String password, String encodedPrivateKey, boolean isCompressed)
            throws GeneralSecurityException, UnsupportedEncodingException, AddressFormatException {

        DumpedPrivateKey dk = new DumpedPrivateKey(MainNetParams.get(), encodedPrivateKey);

        ECKey key = dk.getKey();
        byte[] keyBytes = key.getPrivKeyBytes();
        String address = key.toAddress(MainNetParams.get()).toString();
        byte[] tmp = address.getBytes("ASCII");
        byte[] hash = Utils.doubleHash(tmp, 0, tmp.length);
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

        byte[] encryptedHalf1 = Utils.AESEncrypt(k1, derivedHalf2);
        byte[] encryptedHalf2 = Utils.AESEncrypt(k2, derivedHalf2);

        //byte[] encryptedPrivateKey = new byte[39];
        byte[] header = { 0x01, 0x42, (byte) (isCompressed ? 0xe0 : 0xc0) };
        /*encryptedPrivateKey[0] = 0x01;
        encryptedPrivateKey[1] = 0x42;
        encryptedPrivateKey[2] = (byte) (isCompressed ? 0xe0 : 0xc0);
        System.arraycopy(addressHash, 0, encryptedPrivateKey, 3, 4);
        System.arraycopy(encryptedHalf1, 0, encryptedPrivateKey, 7, 16);
        System.arraycopy(encryptedHalf2, 0, encryptedPrivateKey, 23, 16);*/
        byte[] encryptedPrivateKey = Utils.concat(header, addressHash, encryptedHalf1, encryptedHalf2);

        return Utils.base58Check(encryptedPrivateKey);
    }

    /**
     * Decrypts a key that was encrypted without EC multiplication.
     * @param password
     * @param encryptedKey
     * @return the key, Base58-encoded
     * @throws UnsupportedEncodingException
     * @throws GeneralSecurityException
     */
    public static String decryptNoEC(String password, byte[] encryptedKey) throws UnsupportedEncodingException, GeneralSecurityException{

        byte[] addressHash =  Arrays.copyOfRange(encryptedKey, 3, 7);
        byte[] scryptKey = SCrypt.scrypt(password.getBytes("UTF8"), addressHash, 16384, 8, 8, 64);
        byte[] derivedHalf1 = Arrays.copyOfRange(scryptKey, 0, 32);
        byte[] derivedHalf2 = Arrays.copyOfRange(scryptKey, 32, 64);

        byte[] encryptedHalf1 = Arrays.copyOfRange(encryptedKey, 7, 23);
        byte[] encryptedHalf2 = Arrays.copyOfRange(encryptedKey, 23, 39);
        byte[] k1 = Utils.AESDecrypt(encryptedHalf1, derivedHalf2);
        byte[] k2 = Utils.AESDecrypt(encryptedHalf2, derivedHalf2);
        byte[] keyBytes = new byte[32];
        for (int i = 0; i < 16; i++) {
            keyBytes[i] = (byte) (k1[i] ^ derivedHalf1[i]);
            keyBytes[i + 16] = (byte) (k2[i] ^ derivedHalf1[i + 16]);
        }
        boolean compressed = (keyBytes[2] & (byte) 0xe0) == 0;
        ECKey k = new ECKey(new BigInteger(1, keyBytes), null, compressed);
        return k.getPrivateKeyEncoded(MainNetParams.get()).toString();
    }

    // command line encryption and decryption.
    public static void main(String args[]) throws Exception {
        switch(args.length) {
            case 3:
                if (args[0].equals("-e")) {
                    System.out.println(encryptNoEC(args[1], args[2], false));
                }
                else if (args[0].equals("-d")) {
                    System.out.println(decrypt(args[1], args[2]));
                }
                else usage();
                break;
            default:
                usage();
        }
    }

    private static void usage() {
        System.out.println("Usage: BIP38 [-d|-e] [passphrase] [key]\nEncrypts or decrypts a key.");
    }
}