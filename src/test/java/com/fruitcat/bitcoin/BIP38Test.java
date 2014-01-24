package com.fruitcat.bitcoin;

import com.google.bitcoin.core.Base58;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;

import java.util.Arrays;
import java.util.Random;

/**
 * Unit tests
 *
 */
public class BIP38Test {

    String testPass = "TestingOneTwoThree";

    @Test
    public void noCompressionNoECMultiply() throws Exception {
        //test 1
        String encryptedKey = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg";
        String key = "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR";
        String decryptedKey = BIP38.decrypt(testPass, encryptedKey);
        assertEquals(key, decryptedKey);
        //test 2
        encryptedKey = "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq";
        key = "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5";
        decryptedKey = BIP38.decrypt("Satoshi", encryptedKey);
        assertEquals(key, decryptedKey);
    }

    @Test
    public void compressionNoECMultiply() throws Exception {
        //test 1
        String encryptedKey = "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo";
        String key = "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP";
        String decryptedKey = BIP38.decrypt(testPass, encryptedKey);
        assertEquals(key, decryptedKey);
        //test 2
        encryptedKey = "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7";
        key =  "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7";
        decryptedKey = BIP38.decrypt("Satoshi", encryptedKey);
        assertEquals(key, decryptedKey);
    }

    //EC multiply, no compression, no lot/sequence numbers
    @Test
    public void ecMultiplyNoCompressionNoLot() throws Exception {
        //test 1
        String encryptedKey = "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX";
        String key = "5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2";
        String decryptedKey = BIP38.decrypt(testPass, encryptedKey);
        long ls = Utils.getLotSequence(encryptedKey);
        assertEquals(key, decryptedKey);
        assertEquals(-1, ls / 4096);
        assertEquals(-1, ls % 4096);
        //test 2
        key = "5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH";
        encryptedKey = "6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd";
        decryptedKey = BIP38.decrypt("Satoshi", encryptedKey);
        assertEquals(key, decryptedKey);
        ls = Utils.getLotSequence(encryptedKey);
        assertEquals(key, decryptedKey);
        assertEquals(-1, ls / 4096);
        assertEquals(-1, ls % 4096);
    }

    //EC multiply, no compression, lot/sequence
    @Test
    public void ecMultiplyNoCompressionLot() throws Exception {
        //test 1
        String encryptedKey = "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j";
        String key = "5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8";
        String decryptedKey = BIP38.decrypt("MOLON LABE", encryptedKey);
        long ls = Utils.getLotSequence(encryptedKey);
        assertEquals(ls / 4096, 263183);
        assertEquals(ls % 4096, 1);

        assertEquals(key, decryptedKey);
        //test 2
        encryptedKey = "6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH";
        key = "5KMKKuUmAkiNbA3DazMQiLfDq47qs8MAEThm4yL8R2PhV1ov33D";
        decryptedKey = BIP38.decrypt("ΜΟΛΩΝ ΛΑΒΕ", encryptedKey);
        assertEquals(key, decryptedKey);
        ls = Utils.getLotSequence(encryptedKey);
        assertEquals(ls / 4096, 806938);
        assertEquals(ls % 4096, 1);
    }

    //round encrypt and decrypt with a random ascii password
    @Test
    public void randomRoundTripNoEC() throws Exception {
        byte[] r = new byte[16];
        (new Random()).nextBytes(r);
        String randomPass = new String(r, "ASCII");
        String key = "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR";
        String encryptedKey = BIP38.encryptNoEC(randomPass, key, false);
        assertEquals(key, (BIP38.decrypt(randomPass, encryptedKey)));
    }

    //generate an encrypted key and make sure it looks ok.
    @Test
    public void generateEncryptedKey() throws Exception {
        String k = BIP38.generateEncryptedKey(testPass);
        String dk = BIP38.decrypt(testPass, k);
        assertEquals(dk.charAt(0), '5');
    }

    //check confirmation code
    @Test
    public void checkConfirmation() throws Exception {
        byte[] intermediate = Arrays.copyOfRange(Base58.decode(BIP38.intermediatePassphrase(testPass, -1, -1)), 0, 53);
        GeneratedKey gk = BIP38.encryptedKeyFromIntermediate(intermediate);
        assert(BIP38.verify(testPass, gk));
        assert(!BIP38.verify("garbage", gk));
    }
}