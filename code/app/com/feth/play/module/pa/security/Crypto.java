package com.feth.play.module.pa.security;

/**
 * User: chaschev
 * Date: 11/5/12
 */
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Helper class tp encrypt or decrypt a String.
 *
 * @author niels
 *
 */
public class Crypto {
    public static RuntimeException runtime(Exception e) {
        if (RuntimeException.class.isAssignableFrom(e.getClass())) {
            return (RuntimeException) e;
        } else {
            return new RuntimeException(e);
        }
    }

    /**
     * Encrypt a String with the AES encryption standard. Private key must have a length of 16 bytes
     * @param value The String to encrypt
     * @param privateKey The key used to encrypt
     * @return An hexadecimal encrypted string
     * @throws java.security.InvalidKeyException
     */
    public static String encryptAES(String value, String privateKey)  {
        try {
            byte[] raw = privateKey.getBytes();
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            return String.valueOf(Hex.encodeHex(cipher.doFinal(value.getBytes())));
        } catch (Exception e) {
            throw runtime(e);
        }
    }

    /**
     * Decrypt a String with the AES encryption standard. Private key must have a length of 16 bytes
     *
     * @param value An hexadecimal encrypted string
     * @param privateKey The key used to encrypt
     * @return The decrypted String
     */
    public static String decryptAES(String value, String privateKey) {
        try {
            byte[] raw = privateKey.getBytes();

            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");

            Cipher cipher = Cipher.getInstance("AES");

            cipher.init(Cipher.DECRYPT_MODE, skeySpec);

            return new String(cipher.doFinal(Hex.decodeHex(value.toCharArray())));
        } catch (Exception e) {
            throw runtime(e);
        }
    }


}