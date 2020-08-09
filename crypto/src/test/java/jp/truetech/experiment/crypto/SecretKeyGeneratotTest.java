package jp.truetech.experiment.crypto;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.Test;

public class SecretKeyGeneratotTest {
    
    /*
     * RSA鍵ペア作成
     * openssl genrsa -out privateKey.pem 2048
     * 暗号鍵のラップに使用する公開鍵を取り出す
     * openssl pkey -pubout -in privateKey.pem -inform pem -out publicKey.pem -outform pem
     */

    @Test
    public void test() throws Exception {
        Path publicKeyPath = Paths.get("publicKey.pem");
        Path secretKeyPath = Paths.get("encryptedSecretKey.bin");
        SecretKeyGenerator generator = new SecretKeyGenerator();
        generator.generateSecretKey(publicKeyPath, secretKeyPath);
    }
}
