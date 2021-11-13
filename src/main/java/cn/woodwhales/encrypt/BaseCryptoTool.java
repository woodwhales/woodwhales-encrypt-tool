package cn.woodwhales.encrypt;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @author woodwhales on 2021-11-13 14:16
 */
public class BaseCryptoTool {

    protected static Cipher buildCipher(String algorithm, int mod, SecretKeySpec key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        if(Objects.isNull(iv)) {
            cipher.init(mod, key);
        } else {
            cipher.init(mod, key, iv);
        }
        return cipher;
    }

    protected static Cipher buildEncryptCipher(String algorithm, SecretKeySpec key, IvParameterSpec iv) throws Exception {
        return buildCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv);
    }

    protected static Cipher buildEncryptCipher(String algorithm, SecretKeySpec key) throws Exception {
        return buildCipher(algorithm, Cipher.ENCRYPT_MODE, key, null);
    }

    protected static Cipher buildDecryptCipher(String algorithm, SecretKeySpec key, IvParameterSpec iv) throws Exception {
        return buildCipher(algorithm, Cipher.DECRYPT_MODE, key, iv);
    }

    protected static Cipher buildDecryptCipher(String algorithm, SecretKeySpec key) throws Exception {
        return buildCipher(algorithm, Cipher.DECRYPT_MODE, key, null);
    }

    protected static String encrypt(Cipher encryptCipher, String originContent) throws Exception {
        // 将原始明文转成字节数组
        byte[] originByteContent = originContent.getBytes(UTF_8);

        // 加密
        byte[] enc = encryptCipher.doFinal(originByteContent);

        // 将密文转成使用 base64 编码压缩
        byte[] encode = Base64.getEncoder().encode(enc);

        // 将加密后的数据转成字符明文
        return new String(encode, UTF_8);
    }

    protected static String decrypt(Cipher decryptCipher, String encryptContent) throws Exception {
        // 将密文转成使用 base64 解码解压
        byte[] encryptByteContent = Base64.getDecoder().decode(encryptContent);

        // 解密
        byte[] originByteContent = decryptCipher.doFinal(encryptByteContent);

        // 将解密后的数据转成字符明文
        return new String(originByteContent, UTF_8);
    }

    protected static byte[] checkValue(String value, String valueDescription, int ...exceptLengths) throws Exception {
        if(Objects.isNull(value)) {
            throw new RuntimeException(String.format("%s不允许为空", valueDescription));
        }

        if(Objects.isNull(exceptLengths)) {
            return value.getBytes(UTF_8);
        }

        byte[] valueBytes = value.getBytes(UTF_8);
        boolean matchFlag = false;
        for (int exceptLength : exceptLengths) {
            if(Objects.equals(exceptLength, valueBytes.length)) {
                matchFlag = true;
                break;
            }
        }

        if (!matchFlag) {
            String exceptLengthsDesc = "";
            if(exceptLengths.length == 1) {
                exceptLengthsDesc = exceptLengths[0] + "";
            } else {
                StringBuffer sb = new StringBuffer();
                for (int i = 0; i < exceptLengths.length - 1; i++) {
                    sb.append(exceptLengths[i] + " 或 ");
                }

                sb.append(exceptLengths[exceptLengths.length - 1]);
                exceptLengthsDesc = sb.toString();
            }

            throw new RuntimeException(String.format("%s[ %s ]长度必须为%s", valueDescription, value, exceptLengthsDesc));
        }
        return valueBytes;
    }

    protected static byte[] checkKey(String value, int ...exceptLength) throws Exception {
        return checkValue(value, "密钥", exceptLength);
    }

    protected static byte[] checkIv(String iv, int ...exceptLength) throws Exception {
        return checkValue(iv, "iv偏移量", exceptLength);
    }

    /**
     * 随机生成 16 位的偏移量
     * @return 偏移量 IvParameterSpec
     */
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * 随机生成 16 位的偏移量的 base64 字符串
     * @return 偏移量 IvParameterSpec 的 base64 字符串
     */
    public static String generateIvBase64() {
        IvParameterSpec ivParameterSpec = generateIv();
        return new String(Base64.getEncoder().encode(ivParameterSpec.getIV()), UTF_8);
    }

}
