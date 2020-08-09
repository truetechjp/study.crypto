package jp.truetech.experiment.crypto;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SecretKeyGenerator {

    private SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private byte[] wrapSecretKey(SecretKey seceretKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.WRAP_MODE, publicKey);
        return cipher.wrap(seceretKey);
    }

    private PublicKey loadPublicKey(byte[] bytes) throws Exception {
        EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private byte[] loadPem(Path path) throws Exception {
        List<String> lines = Files.readAllLines(path);
        StringBuilder sb = new StringBuilder();
        lines.stream()
        .filter(s -> !s.startsWith("-----BEGIN "))
        .filter(s -> !s.startsWith("-----END "))
        .forEach(s -> sb.append(s));
        return Base64.getDecoder().decode(sb.toString());
    }

    public void generateSecretKey(Path publicKeyPath, Path secretKeyPath) throws Exception {
        PublicKey publicKey = loadPublicKey(loadPem(publicKeyPath));
        SecretKey secretKey = generateSecretKey();
        byte[] bytes = wrapSecretKey(secretKey, publicKey);
        Files.write(secretKeyPath, bytes, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
    }

}
