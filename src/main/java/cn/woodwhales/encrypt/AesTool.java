package cn.woodwhales.encrypt;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * AES 加解密工具
 * @author woodwhales on 2021-11-13 14:09
 */
public class AesTool extends BaseCryptoTool {

    public static String encryptWithKeyAndIv(String originContent,
                                             String key,
                                             String iv) throws Exception {

        byte[] ivBytes = checkIv(iv, 16);
        byte[] keyBytes = checkKey(key, new int[]{16, 24, 32});
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = buildEncryptCipher("AES/CBC/PKCS5Padding", secretKeySpec, ivParameterSpec);
        return encrypt(cipher, originContent);
    }

    public static String decryptWithKeyAndIv(String originContent,
                                             String key,
                                             String iv) throws Exception {
        byte[] ivBytes = checkIv(iv, 16);
        byte[] keyBytes = checkKey(key, new int[]{16, 24, 32});
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = buildDecryptCipher("AES/CBC/PKCS5Padding", secretKeySpec, ivParameterSpec);
        return decrypt(cipher, originContent);
    }

    /**
     * 加密（AES/ECB/PKCS5Padding）
     * 不推荐使用
     * @param originContent 原始明文
     * @param key 密钥
     * @return 密文
     * @throws Exception Exception
     */
    public static String encryptWithKey(String originContent, String key) throws Exception {
        byte[] keyBytes = checkKey(key, 16);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = buildEncryptCipher("AES/ECB/PKCS5Padding", secretKeySpec);
        return encrypt(cipher, originContent);
    }

    /**
     * 解密（AES/ECB/PKCS5Padding）
     *  不推荐使用
     * @param encryptContent 加密密文
     * @param key 密钥
     * @return 明文
     * @throws Exception Exception
     */
    public static String decryptWithKey(String encryptContent, String key) throws Exception {
        byte[] keyBytes = checkKey(key, 16);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = buildDecryptCipher("AES/ECB/PKCS5Padding", secretKeySpec);
        return decrypt(cipher, encryptContent);
    }

    /**
     * 随机生成密钥
     * @param n 生成的位数
     * @return 指定位数的密钥
     */
    public static SecretKey generateKey(int n) {
        if(!(Objects.equals(n, 128) ||
                Objects.equals(n, 192)
                || Objects.equals(n, 256)
            )) {
            throw new RuntimeException("参数必须为 128 或者 192 或者 256");
        }

        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(n);
            SecretKey key = keyGenerator.generateKey();
            return key;
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

}
