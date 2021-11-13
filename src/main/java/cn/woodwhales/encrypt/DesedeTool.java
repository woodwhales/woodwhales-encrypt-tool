package cn.woodwhales.encrypt;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 3DES 加解密工具
 * @author woodwhales on 2021-11-13 17:36
 */
public class DesedeTool extends BaseCryptoTool {

    private static String algorithm = "DESede";

    /**
     * 加密（DESede/ECB/PKCS5Padding）
     * 不推荐使用
     * @param originContent 原始明文
     * @param key 密钥
     * @return 密文
     * @throws Exception Exception
     */
    public static String encryptWithKey(String originContent, String key) throws Exception {
        byte[] keyBytes = checkKey(key, 24);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, algorithm);
        Cipher cipher = buildEncryptCipher("DESede/ECB/PKCS5Padding", secretKeySpec);
        return encrypt(cipher, originContent);
    }

    /**
     * 解密（DESede/ECB/PKCS5Padding）
     *  不推荐使用
     * @param encryptContent 加密密文
     * @param key 密钥
     * @return 明文
     * @throws Exception Exception
     */
    public static String decryptWithKey(String encryptContent, String key) throws Exception {
        byte[] keyBytes = checkKey(key, 24);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, algorithm);
        Cipher cipher = buildDecryptCipher("DESede/ECB/PKCS5Padding", secretKeySpec);
        return decrypt(cipher, encryptContent);
    }

    /**
     * 加密
     * @param originContent 原始明文
     * @param key 密钥
     * @param iv 偏移量
     * @return 密文
     * @throws Exception Exception
     */
    public static String encryptWithKeyAndIv(String originContent, String key, String iv) throws Exception {
        byte[] ivBytes = checkIv(iv, 8);
        byte[] keyBytes = checkKey(key, 24);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, algorithm);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = buildEncryptCipher("DESede/CBC/PKCS5Padding", secretKeySpec, ivParameterSpec);
        return encrypt(cipher, originContent);
    }

    /**
     * 解密
     * @param encryptContent 密文
     * @param key 密钥
     * @param iv 偏移量
     * @return 明文
     * @throws Exception Exception
     */
    public static String decryptWithKeyAndIv(String encryptContent, String key, String iv) throws Exception {
        byte[] ivBytes = checkIv(iv, 8);
        byte[] keyBytes = checkKey(key, 24);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, algorithm);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = buildDecryptCipher("DESede/CBC/PKCS5Padding", secretKeySpec, ivParameterSpec);
        return decrypt(cipher, encryptContent);
    }

}
