package com.fruitcat.bitcoin;

import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;

/**
 * Unit tests
 *
 */
public class BIP38Test {

    //EC multiply, no compression, no lot/sequence numbers
    @Test
    public void decryptECNoCompressionNoLotTest() throws Exception {
        String encryptedKey = "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX";
        String pass = "TestingOneTwoThree";
        String key = "5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2";
        String decryptedKey = BIP38.decrypt(pass, encryptedKey);
        assertEquals(key, decryptedKey);
    }

    @Test
    public void decryptNoECNoCompression() throws Exception {
        String encryptedKey = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg";
        String pass = "TestingOneTwoThree";
        String key = "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR";
        String decryptedKey = BIP38.decrypt(pass, encryptedKey);
        assertEquals(key, decryptedKey);

    }
}
