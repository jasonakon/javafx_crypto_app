package org.example.crypto;

import javax.crypto.Cipher;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RsaUtil {

    public static final String RSA = "RSA";
    public static final String SIGNED_ALGO = "SHA256withRSA";

    private RsaUtil() {
       throw new IllegalStateException("RsaUtil");
    }


    public static String encrypt(String plainText, PublicKey publicKey) throws NoSuchAlgorithmException
            ,javax.crypto.NoSuchPaddingException, InvalidKeyException
            , javax.crypto.IllegalBlockSizeException, javax.crypto.BadPaddingException{
        Cipher encryptCipher = Cipher.getInstance(RSA);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws NoSuchAlgorithmException
            ,javax.crypto.NoSuchPaddingException, InvalidKeyException
            , javax.crypto.IllegalBlockSizeException, javax.crypto.BadPaddingException{
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance(RSA);
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    public static String sign(String plainText, PrivateKey privateKey) throws NoSuchAlgorithmException
            , SignatureException, InvalidKeyException {
        Signature privateSignature = Signature.getInstance(SIGNED_ALGO);
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public static PublicKey getRsaPublic(String key){
        PublicKey publicKey = null;
        try{
            byte[] byteKey = Base64.getDecoder().decode(key.getBytes());
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(byteKey);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
        } catch (InvalidKeySpecException e){
            System.out.println(e.getMessage());
        }
        return publicKey;
    }

    public static PrivateKey getRsaPrivate(String key){
        PrivateKey privateKey = null;
        try{
            byte[] byteKey = Base64.getDecoder().decode(key.getBytes());
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(byteKey);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            privateKey = keyFactory.generatePrivate(keySpec);
            System.out.println("test");
            return privateKey;
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
        } catch (InvalidKeySpecException e){
            System.out.println(e.getMessage());
        }
        return privateKey;
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance(SIGNED_ALGO);
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    public static RsaKeys generateRsaKeys(int size){
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA);
            keyGen.initialize(size);
            KeyPair pair = keyGen.generateKeyPair();
            String pub = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
            String priv = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
            System.out.println("privateKey: " + priv);
            System.out.println("publicKey: " + pub);
            RsaKeys keys = new RsaKeys();
            keys.setPrivateKey(priv);
            keys.setPublicKey(pub);

            File rsaPublicFile = new File("rsa_public.txt");
            FileOutputStream rsaPublicOutputStream = new FileOutputStream(rsaPublicFile);
            rsaPublicOutputStream.write(pub.getBytes());
            rsaPublicOutputStream.close();

            File rsaPrivateFile = new File("rsa_private.txt");
            FileOutputStream rsaPrivateOutputStream = new FileOutputStream(rsaPrivateFile);
            rsaPrivateOutputStream.write(priv.getBytes());
            rsaPrivateOutputStream.close();

            return keys;
        }catch (NoSuchAlgorithmException | IOException e){
            System.out.println(e.getMessage());
        }
        return null;
    }


}
