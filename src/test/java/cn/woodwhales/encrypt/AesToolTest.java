package cn.woodwhales.encrypt;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author woodwhales on 2021-11-13 14:09
 */
public class AesToolTest {

    String originContent = "abcdef";
    String key = "1234567812345678";
    String iv =  "012345678abcdeff";

    @Test
    public void testEncryptWithKey() throws Exception {
        String encrypt = AesTool.encryptWithKey(originContent, key);
        String decrypt = AesTool.decryptWithKey(encrypt, key);
        System.out.println("encrypt = " + encrypt);
        System.out.println("decrypt = " + decrypt);
        Assertions.assertEquals(originContent, decrypt);
    }

    @Test
    public void testEncryptWithKeyAndIv() throws Exception {
        String encrypt = AesTool.encryptWithKeyAndIv(originContent, key, iv);
        String decrypt = AesTool.decryptWithKeyAndIv(encrypt, key, iv);
        System.out.println("encrypt = " + encrypt);
        System.out.println("decrypt = " + decrypt);
        Assertions.assertEquals(originContent, decrypt);
    }
}
