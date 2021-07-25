package org.example.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.spec.KeySpec;

public class AESCryptography {
	public static final String ALGORITHM_AES = "AES";
	public static final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
	public static final String TRANSFORMATION_AES = "AES/CBC/PKCS5Padding";
	
	private static final String salt = "Platform";
		
	/**
	 * Process a file (Encrypts or decrypts depending on cipherMode)
	 * @param encrypt
	 * @param inputFile
	 * @param inputKey
	 * @param outputFile
	 * @throws Exception
	 */
    private static void processFile(boolean encrypt, File inputFile, String inputKey, File outputFile) throws Exception {
        // Convert key into bytes       
        SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
        KeySpec spec = new PBEKeySpec(inputKey.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), ALGORITHM_AES);
        
        byte[] ivBytes = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        
        // Get cipher instance        
        Cipher cipher = Cipher.getInstance(TRANSFORMATION_AES);
        if(encrypt) {
        	cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        }
        else {
        	cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        }

        // Read input file into byte array
        FileInputStream fileInputStream = new FileInputStream(inputFile);
        byte[] inputBytes = new byte[(int)inputFile.length()];
        fileInputStream.read(inputBytes);

        // Process the byte array from the input file
        byte[] outputBytes = cipher.doFinal(inputBytes);

        // Write the output byte array to the output file
        FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
        fileOutputStream.write(outputBytes);

        // Close file streams
        fileInputStream.close();
        fileOutputStream.close();
    }

	/**
	 * Encrypts a file
	 * @param inputFile
	 * @param inputKey
	 * @param outputFile
	 * @throws Exception
	 */
    public static void encrypt(File inputFile, String inputKey, File outputFile) throws Exception {
        processFile(true,inputFile,inputKey,outputFile);
    }

    /**
     * Decrypts a file
     * @param inputFile
     * @param inputKey
     * @param outputFile
     * @throws Exception
     */
    public static void decrypt(File inputFile, String inputKey, File outputFile) throws Exception {
        processFile(false,inputFile,inputKey,outputFile);
    }

}
