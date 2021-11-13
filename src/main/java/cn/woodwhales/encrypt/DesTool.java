package cn.woodwhales.encrypt;


import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

/**
 * EDS 加解密工具
 *
 * @author woodwhales on 2021-11-12 14:50
 */
public class DesTool extends BaseCryptoTool {

    private static String algorithm = "DES";

    /**
     * 加密
     * @param originContent 原始明文
     * @param key 密钥
     * @param iv 偏移量
     * @return 密文
     * @throws Exception Exception
     */
    public static String encryptWithKeyAndIv(String originContent, String key, String iv) throws Exception {
        return encrypt(encryptAndDecryptWithKeyAndIv(key, iv, Cipher.ENCRYPT_MODE), originContent);
    }

    /**
     * 解密
     * @param encryptContent 加密密文
     * @param key 密钥
     * @param iv 偏移量
     * @return 明文
     * @throws Exception Exception
     */
    public static String decryptWithKeyAndIv(String encryptContent, String key, String iv) throws Exception {
        return decrypt(encryptAndDecryptWithKeyAndIv(key, iv, Cipher.DECRYPT_MODE), encryptContent);
    }

    /**
     * 加密（DES/ECB/PACKS5padding）
     * @param originContent 原始明文
     * @param key 密钥
     * @return 密文
     * @throws Exception Exception
     */
    public static String encryptWithKey(String originContent, String key) throws Exception {
        return encrypt(encryptAndDecryptWithKey(key, Cipher.ENCRYPT_MODE), originContent);
    }

    /**
     * 解密（DES/ECB/PACKS5padding）
     * @param encryptContent 加密密文
     * @param key 密钥
     * @return 明文
     * @throws Exception Exception
     */
    public static String decryptWithKey(String encryptContent, String key) throws Exception {
        return decrypt(encryptAndDecryptWithKey(key, Cipher.DECRYPT_MODE), encryptContent);
    }

    private static Cipher encryptAndDecryptWithKeyAndIv(String key, String iv, int mode) throws Exception {
        byte[] keyBytes = checkKey(key, 8);
        byte[] ivBytes = checkIv(iv, 8);

        DESKeySpec desKeySpec = new DESKeySpec(keyBytes);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        Key secretKey = keyFactory.generateSecret(desKeySpec);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        cipher.init(mode, secretKey, ivParameterSpec);
        return cipher;
    }

    private static Cipher encryptAndDecryptWithKey(String key, int mode) throws Exception {
        byte[] keyBytes = checkKey(key, 8);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(mode, secretKeySpec);
        return cipher;
    }
}
