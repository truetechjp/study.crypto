package jp.truetech.experiment.crypto;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class KeyLoader {

    public SecretKey loadSecretKey(Path privateKey, Path wrappedKey) throws Exception {
        if (!privateKey.toFile().exists()) {
            throw new IllegalArgumentException("秘密鍵ファイルがありません: " + privateKey);
        }
        if (!wrappedKey.toFile().exists()) {
            throw new IllegalArgumentException("暗号鍵ファイルがありません: " + wrappedKey);
        }
        return loadSecretKey(Files.readAllBytes(privateKey), Files.readAllBytes(wrappedKey));
    }


    SecretKey loadSecretKey(byte[] privateKeyBytes, byte[] wrappedKeyBytes) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.UNWRAP_MODE, privateKey);
        return (SecretKey) cipher.unwrap(wrappedKeyBytes, "RSA", Cipher.SECRET_KEY);
    }
}