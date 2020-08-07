package jp.truetech.experiment.crypto;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoDemo {
    
    static private final String KEYPAIR_ALGORITHM = "RSA";
    static private final String SECRETKEY_ALGORITHM = "AES";
    static private final int SECRETKEY_SIZE = 256;

    /*
     * 
     * $ openssl genrsa -out privatekey.pem 2048 
     * $ openssl pkcs8 -in privatekey.pem -topk8 -nocrypt -outform der -out privatekey.pk8.der
     * $ openssl pkey -pubout -out publickey.pem -outform pem -in privatekey.pem -inform pem
     * $ java Crypto secretkey publickey.pem secretkey.der
     * 
     * $ java Crypto encrypt secretkey.der privatekey.pk8.der x "Hello"
     * privateKeyFile: privatekey.pk8.der
     * secretKeyFile: secretkey.der
     * iv: aqmM7UvA+b+o2+IKz2/GGw== 
     * encrypted: UV/vboa8gVOiZSVSSDV/pA==
     * 
     * $ java Crypto decrypt secretkey.der privatekey.pk8.der aqmM7UvA+b+o2+IKz2/GGw== UV/vboa8gVOiZSVSSDV/pA==
     * privateKeyFile: privatekey.pk8.der
     * secretKeyFile: secretkey.der
     * decrypted: Hello
     * 
     */
    
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printProviders();
            return;
        }

        int i = 0;
        String operation = args[i++];
        switch (operation) {

        case "secretkey": {
            File secretKeyFile = new File(args[i++]);
            File pulicKeyPemFile = new File(args[i++]);
            secretKey(pulicKeyPemFile, secretKeyFile);
            return;
        }

        case "iv": {
            System.out.println(encodeToBase64String(iv()));
            return;
        }

        case "encrypt": {
            File secretKeyFile = new File(args[i++]);
            File privateKeyFile = new File(args[i++]);
            String ivB64 = args[i++];
            String s = args[i++];
            encrypt(secretKeyFile, privateKeyFile, ivB64, s);
            return;
        }

        case "decrypt": {
            File secretKeyFile = new File(args[i++]);
            File privateKeyFile = new File(args[i++]);
            String ivB64 = args[i++];
            String s = args[i++];
            decrypt(secretKeyFile, privateKeyFile, ivB64, s);
            return;
        }

        }
    }

    private static void secretKey(File publicKeyPemFile, File secretKeyFile) throws Exception {
        log("publicKeyPemFile: " + publicKeyPemFile);
        log("secretKeyFile: " + secretKeyFile);
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SECRETKEY_ALGORITHM);
        keyGenerator.init(SECRETKEY_SIZE);
        Key key = keyGenerator.generateKey();
        PublicKey publicKey = generatePublicKey(loadPem(publicKeyPemFile));
        byte[] wrappedKey = wrapSecretKey(key, publicKey);
        save(secretKeyFile, wrappedKey);
    }

    private static void encrypt(File secretKeyFile, File privateKeyFile, String ivB64, String plainText)
            throws Exception {
        log("secretKeyFile: " + secretKeyFile);
        log("privateKeyFile: " + privateKeyFile);
        PrivateKey privateKey = generatePrivateKey(load(privateKeyFile));
        SecretKey secretKey = unwrapSecretKey(load(secretKeyFile), privateKey);
        byte[] iv = decodeBase64(ivB64);
        byte[] encrypted = new CryptoDemo().encrypt(secretKey, iv, plainText.getBytes());
        log("iv: " + ivB64);
        log("encrypted: " + encodeToBase64String(encrypted));
    }

    private static void decrypt(File secretKeyFile, File privateKeyFile, String ivB64, String encryptedB64)
            throws Exception {
        log("secretKeyFile: " + secretKeyFile);
        log("privateKeyFile: " + privateKeyFile);
        PrivateKey privateKey = generatePrivateKey(load(privateKeyFile));
        SecretKey secretKey = unwrapSecretKey(load(secretKeyFile), privateKey);
        byte[] decrypted = new CryptoDemo().decrypt(secretKey, decodeBase64(ivB64), decodeBase64(encryptedB64));
        log("iv: " + ivB64);
        log("decrypted: " + new String(decrypted));
    }

    static private PublicKey generatePublicKey(byte[] encodedKey) throws Exception {
        EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance(KEYPAIR_ALGORITHM);
        return keyFactory.generatePublic(keySpec);
    }

    private static PrivateKey generatePrivateKey(byte[] encodedKey) throws Exception {
        EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance(KEYPAIR_ALGORITHM);
        return keyFactory.generatePrivate(keySpec);
    }

    private static byte[] wrapSecretKey(Key key, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(KEYPAIR_ALGORITHM);
        cipher.init(Cipher.WRAP_MODE, publicKey);
        return cipher.wrap(key);
    }

    static private SecretKey unwrapSecretKey(byte[] wrappedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(KEYPAIR_ALGORITHM);
        cipher.init(Cipher.UNWRAP_MODE, privateKey);
        return (SecretKey) cipher.unwrap(wrappedKey, KEYPAIR_ALGORITHM, Cipher.SECRET_KEY);
    }

    private static void save(File file, byte[] bytes) throws Exception {
        try (OutputStream out = new FileOutputStream(file)) {
            out.write(bytes);
        }
    }

    static private byte[] load(File file) throws Exception {
        try (InputStream in = new FileInputStream(file)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            while (true) {
                int i = in.read();
                if (i == -1) {
                    out.close();
                    return out.toByteArray();
                }
                out.write(i);
            }
        }
    }

    static private byte[] loadPem(File file) throws Exception {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            StringBuilder sb = new StringBuilder();
            while (true) {
                String line = reader.readLine();
                if (line == null) {
                    break;
                }
                if (line.startsWith("-----BEGIN ") || line.startsWith("-----END "))
                    continue;
                sb.append(line);
            }
            return decodeBase64(sb.toString());
        }
    }

    static private byte[] decodeBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    static private String encodeToBase64String(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    static private byte[] iv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private byte[] encrypt(SecretKey secretKey, byte[] iv, byte[] plain) throws Exception {
        return doCrypt(Cipher.ENCRYPT_MODE, secretKey, iv, plain);
    }

    private byte[] decrypt(SecretKey secretKey, byte[] iv, byte[] encrypted) throws Exception {
        return doCrypt(Cipher.DECRYPT_MODE, secretKey, iv, encrypted);
    }

    private byte[] doCrypt(int mode, SecretKey secretKey, byte[] iv, byte[] bytes) throws Exception {
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), SECRETKEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(mode, keySpec, ivParam);
        return cipher.doFinal(bytes);
    }

    private static void log(String s) {
        System.out.println(s);
    }

    private static void printProviders() {
        Arrays.stream(Security.getProviders()).forEach(e -> {
            log(e.getInfo());
            printServices(e);
        });
    }

    private static void printServices(Provider provider) {
        provider.getServices().stream().forEach(e -> log("    " + e.toString()));
    }
}
