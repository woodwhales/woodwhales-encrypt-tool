package cn.woodwhales.encrypt;


import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;
import java.util.Objects;

/**
 * EDS 加解密工具
 *
 * @author woodwhales on 2021-11-12 14:50
 */
public class DesTool {

    private static String charsetName = "UTF-8";
    private static String algorithm = "DES";
    private static int keyBytesLength = 8;
    private static int ivBytesLength = 8;

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
     * 加密
     * @param originContent 原始明文
     * @param key 密钥
     * @return 密文
     * @throws Exception Exception
     */
    public static String encryptWithKey(String originContent, String key) throws Exception {
        return encrypt(encryptAndDecryptWithKey(key, Cipher.ENCRYPT_MODE), originContent);
    }

    /**
     * 解密
     * @param encryptContent 加密密文
     * @param key 密钥
     * @return 明文
     * @throws Exception Exception
     */
    public static String decryptWithKey(String encryptContent, String key) throws Exception {
        return decrypt(encryptAndDecryptWithKey(key, Cipher.DECRYPT_MODE), encryptContent);
    }

    private static Cipher encryptAndDecryptWithKeyAndIv(String key, String iv, int mode) throws Exception {
        byte[] keyBytes = checkKey(key);
        byte[] ivBytes = checkIv(iv);

        DESKeySpec desKeySpec = new DESKeySpec(keyBytes);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        Key secretKey = keyFactory.generateSecret(desKeySpec);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        cipher.init(mode, secretKey, ivParameterSpec);
        return cipher;
    }

    private static byte[] checkIv(String iv) throws Exception {
        if(Objects.isNull(iv)) {
            throw new RuntimeException(String.format("偏移量不允许为空"));
        }

        byte[] ivBytes = iv.getBytes(charsetName);
        if (!Objects.equals(ivBytes.length, ivBytesLength)) {
            throw new RuntimeException(String.format("偏移量[ %s ]长度必须为8", iv));
        }
        return ivBytes;
    }

    private static Cipher encryptAndDecryptWithKey(String key, int mode) throws Exception {
        byte[] keyBytes = checkKey(key);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, algorithm);
        // DES/ECB/PACKS5padding
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(mode, secretKeySpec);
        return cipher;
    }

    private static byte[] checkKey(String key) throws Exception {
        if(Objects.isNull(key)) {
            throw new RuntimeException(String.format("密钥不允许为空"));
        }

        byte[] keyBytes = key.getBytes(charsetName);
        if (!Objects.equals(keyBytes.length, keyBytesLength)) {
            throw new RuntimeException(String.format("密钥[ %s ]长度必须为8", key));
        }
        return keyBytes;
    }

    private static String encrypt(Cipher encryptCipher, String originContent) throws Exception {
        // 将原始明文转成字节数组
        byte[] originByteContent = originContent.getBytes(charsetName);

        // 加密
        byte[] enc = encryptCipher.doFinal(originByteContent);

        // 将密文转成使用 base64 编码压缩
        byte[] encode = Base64.getEncoder().encode(enc);

        // 将加密后的数据转成字符明文
        return new String(encode, charsetName);
    }

    private static String decrypt(Cipher decryptCipher, String encryptContent) throws Exception {
        // 将密文转成使用 base64 解码解压
        byte[] encryptByteContent = Base64.getDecoder().decode(encryptContent);

        // 解密
        byte[] originByteContent = decryptCipher.doFinal(encryptByteContent);

        // 将解密后的数据转成字符明文
        return new String(originByteContent, charsetName);
    }
}
