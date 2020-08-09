package jp.truetech.experiment.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {
    static private SecretKey secretKey;

    static void setSecretKey(SecretKey secretKey) {
        Crypto.secretKey = secretKey;
    }

    static byte[] decrypt(byte[] bytes, byte[] iv) throws Exception {
        if (secretKey == null) {
            throw new IllegalStateException("暗号鍵が未設定です");
        }
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParam);
        return cipher.doFinal(bytes);
    }

    static byte[] encrypt(byte[] bytes, byte[] iv) throws Exception {
        if (secretKey == null) {
            throw new IllegalStateException("暗号鍵が未設定です");
        }
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParam);
        return cipher.doFinal(bytes);
    }
}
