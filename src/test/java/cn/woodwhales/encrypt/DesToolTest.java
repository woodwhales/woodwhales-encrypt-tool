package cn.woodwhales.encrypt;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class DesToolTest {

    String originContent = "abcde";
    String key = "12345678";
    String iv = "56781234";

    @Test
    public void testEncryptWithoutKey() throws Exception {
        String encrypt = DesTool.encryptWithKey(originContent, key);
        String decrypt = DesTool.decryptWithKey(encrypt, key);
        Assertions.assertEquals(originContent, decrypt);

        System.out.println("encrypt = " + encrypt);
        System.out.println("decrypt = " + decrypt);
    }

    @Test
    public void testEncryptWithKeyAndIv() throws Exception {
        String encrypt = DesTool.encryptWithKeyAndIv(originContent, key, iv);
        String decrypt = DesTool.decryptWithKeyAndIv(encrypt, key, iv);
        Assertions.assertEquals(originContent, decrypt);

        System.out.println("encrypt = " + encrypt);
        System.out.println("decrypt = " + decrypt);
    }

}