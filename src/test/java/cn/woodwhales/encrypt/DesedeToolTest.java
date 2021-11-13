package cn.woodwhales.encrypt;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author woodwhales on 2021-11-13 17:40
 */
public class DesedeToolTest {

    String originContent = "a123";
    String key = "123456781234567812345678";
    String iv =  "12345678";

    @Test
    public void testEncryptWithKey() throws Exception {
        String encrypt = DesedeTool.encryptWithKey(originContent, key);
        String decrypt = DesedeTool.decryptWithKey(encrypt, key);
        System.out.println("encrypt = " + encrypt);
        System.out.println("decrypt = " + decrypt);
        Assertions.assertEquals(originContent, decrypt);
    }

    @Test
    public void testEncryptWithoutKeyAndIv() throws Exception {
        String encrypt = DesedeTool.encryptWithKeyAndIv(originContent, key, iv);
        String decrypt = DesedeTool.decryptWithKeyAndIv(encrypt, key, iv);

        System.out.println("encrypt = " + encrypt);
        System.out.println("decrypt = " + decrypt);
        Assertions.assertEquals(originContent, decrypt);
    }

}
