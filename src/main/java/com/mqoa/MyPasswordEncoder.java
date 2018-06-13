package com.mqoa;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * @author lidong9144@163.com 2018/6/12
 */
public class MyPasswordEncoder implements PasswordEncoder {

    private static final Logger logger = LoggerFactory.getLogger(MyPasswordEncoder.class);

    public static final int SALT_SIZE = 8;
    public static final int HASH_INTERATIONS = 1024;
    private static final String SHA1 = "SHA-1";
    private static SecureRandom random = new SecureRandom();

    @Override
    public String encode(CharSequence charSequence) {
        byte[] salt = generateSalt(SALT_SIZE);
        byte[] hashPassword = sha1(charSequence.toString().getBytes(), salt, HASH_INTERATIONS);
        return encodeHex(salt) + encodeHex(hashPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodePassword) {
        if (rawPassword == null) {
            return false;
        }

        byte[] salt = decodeHex(encodePassword.substring(0,16));
        byte[] hashPassword = sha1(rawPassword.toString().getBytes(), salt, HASH_INTERATIONS);

        String pass = encodeHex(salt) + encodeHex(hashPassword);

        logger.info("matches方法：rawPassword：{}，encodePassword：{}，pass：{}", rawPassword, encodePassword, pass);

        //比较密码是否相等的问题
        return pass.equals(encodePassword);
    }

    public String encodeHex(byte[] input) {
        return new String(Hex.encodeHex(input));
    }

    private byte[] generateSalt(int numBytes) {
        byte[] bytes = new byte[numBytes];
        random.nextBytes(bytes);
        return bytes;
    }

    private byte[] sha1(byte[] input, byte[] salt, int iterations) {
        return digest(input, SHA1, salt, iterations);
    }

    private byte[] digest(byte[] input, String algorithm, byte[] salt, int iterations) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);

            if (salt != null) {
                digest.update(salt);
            }

            byte[] result = digest.digest(input);

            for (int i = 1; i < iterations; i++) {
                digest.reset();
                result = digest.digest(result);
            }
            return result;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] decodeHex(String input) {
        try {
            return Hex.decodeHex(input.toCharArray());
        } catch (DecoderException e) {
            throw new RuntimeException(e);
        }
    }

}
