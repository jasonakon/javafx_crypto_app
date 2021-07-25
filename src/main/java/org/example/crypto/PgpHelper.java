package org.example.crypto;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import static org.bouncycastle.bcpg.CompressionAlgorithmTags.*;
import static org.bouncycastle.bcpg.PublicKeyAlgorithmTags.RSA_ENCRYPT;
import static org.bouncycastle.bcpg.PublicKeyAlgorithmTags.RSA_SIGN;
import static org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.CAST5;

/**
 * PGP Encryption & Decryption
 *
 * @author
 *
 */
public class PgpHelper {

    private static final int BUFFER_SIZE = 1 << 16; // should always be power of 2
    private static final int KEY_FLAGS = 27;
    private static final int[] MASTER_KEY_CERTIFICATION_TYPES = new int[]{PGPSignature.POSITIVE_CERTIFICATION, PGPSignature.CASUAL_CERTIFICATION,
            PGPSignature.NO_CERTIFICATION, PGPSignature.DEFAULT_CERTIFICATION};

    private static final BigInteger DEFAULT_PUBEXP= BigInteger.valueOf(0x10001);
    //private static final Logger LOGGER = LogManager.getLogger(PgpHelper.class);

    private PgpHelper() { throw new IllegalStateException("Utility class");}

    /**
     * Read public key from a filename
     *
     * @param fileName the name of the file
     * @return the PGPPublic key object
     * @throws IOException
     * @throws PGPException
     */
    public static PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPPublicKey pubKey = readPublicKey(keyIn);
        keyIn.close();
        return pubKey;
    }

    private static void writeStreamToLiteralData(OutputStream os, char fileType, String name, InputStream streamData)
            throws IOException {
        int bufferLength = 4096;

        byte[] buff = new byte[bufferLength];
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        try(
        OutputStream pOut = lData.open(os, fileType, name, PGPLiteralData.NOW, buff);
        ) {
            byte[] buffer = new byte[bufferLength];
            int len;
            while ((len = streamData.read(buffer)) > 0) {
                pOut.write(buffer, 0, len);
            }
        }
    }

    /**
     * Read the public key from a InputStream
     *
     * @param in the InputStream object
     * @return the PGPPublicKey object
     * @throws IOException
     * @throws PGPException
     */
    public static PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException {
        PGPPublicKey publicKey = null;
        PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in), new BcKeyFingerprintCalculator());

        // iterate through the key rings.
        Iterator<PGPPublicKeyRing> rIt = keyRingCollection.getKeyRings();
        while (publicKey == null && rIt.hasNext()) {
            PGPPublicKeyRing kRing = rIt.next();
            Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
            while (publicKey == null && kIt.hasNext()) {
                PGPPublicKey key = kIt.next();
                if (key.isEncryptionKey()) {
                    publicKey = key;
                }
            } // end while
        } // end while

        if (publicKey == null) {
            throw new IllegalArgumentException("Can't find public key in the key ring.");
        }
        if (!isForEncryption(publicKey)) {
            throw new IllegalArgumentException("KeyID " + publicKey.getKeyID() + " not flagged for encryption.");
        }

        return publicKey;
    }

    public static PGPSecretKey readSecretKey(InputStream in) throws IOException, PGPException {
        PGPSecretKey secretKey = null;
        PGPSecretKeyRingCollection keyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(in), new BcKeyFingerprintCalculator());
        // We just loop through the collection till we find a key suitable for signing.
        Iterator<PGPSecretKeyRing> rIt = keyRingCollection.getKeyRings();
        while (secretKey == null && rIt.hasNext()) {
            PGPSecretKeyRing keyRing = rIt.next();
            Iterator<PGPSecretKey> kIt = keyRing.getSecretKeys();
            while (secretKey == null && kIt.hasNext()) {
                PGPSecretKey key = kIt.next();
                if (key.isSigningKey()) {
                    secretKey = key;
                }
            } // end while
        } // end while

        // Validate secret key
        if (secretKey == null) {
            throw new IllegalArgumentException("Can't find private key in the key ring.");
        }
        if (!secretKey.isSigningKey()) {
            throw new IllegalArgumentException("Private key does not allow signing.");
        }
//        if (secretKey.getPublicKey().hasRevocation()) {
//            throw new IllegalArgumentException("Private key has been revoked.");
//        }
        if (!hasKeyFlags(secretKey.getPublicKey(), KeyFlags.SIGN_DATA)) {
            throw new IllegalArgumentException("Key cannot be used for signing.");
        }

        return secretKey;
    }

    public static PGPPrivateKey findPrivateKey(PGPSecretKey pgpSecKey, char[] pass) throws PGPException {
        if (pgpSecKey == null)
            return null;

        PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
                .build(pass);
        return pgpSecKey.extractPrivateKey(decryptor);
    }

    public static PGPPrivateKey findPrivateKey(InputStream keyIn, long keyID, char[] pass)
            throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new BcKeyFingerprintCalculator());
        return findPrivateKey(pgpSec.getSecretKey(keyID), pass);
    }

    public static void encryptStream(OutputStream out, PGPPublicKey encKey, PGPSecretKey secretKey, InputStream streamData, String password)
            throws IOException, PGPException {

        Security.addProvider(new BouncyCastleProvider());

        out = new ArmoredOutputStream(out);
        try(
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ) {
            PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(ZLIB);

            PgpHelper.writeStreamToLiteralData(comData.open(bOut), PGPLiteralDataGenerator.BINARY, PGPLiteralData.CONSOLE,
                    streamData);

            comData.close();
            JcePGPDataEncryptorBuilder jce = new JcePGPDataEncryptorBuilder(CAST5).setWithIntegrityPacket(false).setSecureRandom(new SecureRandom()).setProvider("BC");

            PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(jce);

            JcePublicKeyKeyEncryptionMethodGenerator d = new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());

            cPk.addMethod(d);

            byte[] bytes = bOut.toByteArray();
            PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
            try(
                OutputStream cOut = cPk.open(out, bytes.length);
                OutputStream compressedOut = comData.open(cOut, new byte[BUFFER_SIZE]);
                OutputStream literalOut = literalDataGenerator.open(compressedOut, PGPLiteralData.BINARY, "", new Date(),
                        new byte[BUFFER_SIZE]);

            ) {

                // Initialize signature generator
                PGPPrivateKey privateKey = findPrivateKey(secretKey, password.toCharArray());

                if(secretKey!=null) {
                    PGPContentSignerBuilder signerBuilder = new BcPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1);

                    PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(signerBuilder);

                    signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);


                    boolean firstTime = true;
                    Iterator<String> it = secretKey.getPublicKey().getUserIDs();
                    while (it.hasNext() && firstTime) {
                        PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
                        spGen.setSignerUserID(false, it.next());
                        signatureGenerator.setHashedSubpackets(spGen.generate());
                        // Exit the loop after the first iteration
                        firstTime = false;
                    }

                    signatureGenerator.generateOnePassVersion(false).encode(compressedOut);


                    // Main loop - read the "in" stream, compress, encrypt and write to the "out" stream

                    byte[] buf = new byte[BUFFER_SIZE];
                    int len;
                    while ((len = streamData.read(buf)) > 0) {
                        literalOut.write(buf, 0, len);
                        signatureGenerator.update(buf, 0, len);
                    }
                    // Generate the signature, compress, encrypt and write to the "out" stream
                    signatureGenerator.generate().encode(compressedOut);
                }
                cOut.write(bytes);
            }finally {
                System.out.println("in finally clause cleaning up resources.");
                streamData.close();
                literalDataGenerator.close();
                out.close();
            }
        }
    }

    /**
     * Check if key is for encryption
     *
     * @param key
     * @return return true key is for encryption otherwise false
     */
    public static boolean isForEncryption(PGPPublicKey key) {
        if (key.getAlgorithm() == RSA_SIGN || key.getAlgorithm() == PublicKeyAlgorithmTags.DSA
                || key.getAlgorithm() == PublicKeyAlgorithmTags.ECDH
                || key.getAlgorithm() == PublicKeyAlgorithmTags.ECDSA) {
            return false;
        }

        return hasKeyFlags(key, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
    }

    /**
     * Check if has key flag
     *
     * @param encKey
     * @param keyUsage
     * @return return true if has key flag otherwise false
     */
    @SuppressWarnings("unchecked")
    private static boolean hasKeyFlags(PGPPublicKey encKey, int keyUsage) {
        if (encKey.isMasterKey()) {
            for (int i = 0; i != MASTER_KEY_CERTIFICATION_TYPES.length; i++) {
                for (Iterator<PGPSignature> eIt = encKey
                        .getSignaturesOfType(MASTER_KEY_CERTIFICATION_TYPES[i]); eIt.hasNext(); ) {
                    PGPSignature sig = eIt.next();
                    if (!isMatchingUsage(sig, keyUsage)) {
                        return false;
                    }
                }
            }
        } else {
            for (Iterator<PGPSignature> eIt = encKey.getSignaturesOfType(PGPSignature.SUBKEY_BINDING); eIt.hasNext(); ) {
                PGPSignature sig = eIt.next();
                if (!isMatchingUsage(sig, keyUsage)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Check if signature is matching usage
     *
     * @param sig
     * @param keyUsage
     * @return return true is matched otherwise false
     */
    private static boolean isMatchingUsage(PGPSignature sig, int keyUsage) {
        if (sig.hasSubpackets()) {
            PGPSignatureSubpacketVector sv = sig.getHashedSubPackets();
            if (sv.hasSubpacket(KEY_FLAGS)
              && sv.getKeyFlags() == 0 && keyUsage == 0) {
              // code fix suggested by kzt (see comments)
              return false;
            }
        }
        return true;
    }


    public static void generateKeys(OutputStream pubOut, OutputStream privOut, String password)throws PGPException, IOException{
        PGPKeyRingGenerator kg = generateKeyRingGenerator("client@example.com.sg", password.toCharArray(),192,2048,128,new Date());

        PGPPublicKeyRing pkr = kg.generatePublicKeyRing();
        ArmoredOutputStream outStream = new ArmoredOutputStream(pubOut);
        pkr.encode(outStream);
        outStream.close();

        PGPSecretKeyRing skr = kg.generateSecretKeyRing();
        outStream = new ArmoredOutputStream(privOut);
        skr.encode(outStream);
        outStream.close();
    }

   private static PGPKeyRingGenerator generateKeyRingGenerator (String id, char[] pass, int s2kcount,int nBits,int certainty,Date when) throws PGPException {

        RSAKeyPairGenerator  kpg = new RSAKeyPairGenerator();
        RSAKeyGenerationParameters kgp = new RSAKeyGenerationParameters (DEFAULT_PUBEXP,new SecureRandom(), nBits, certainty);
        kpg.init(kgp);
        PGPKeyPair rsakpSign = new BcPGPKeyPair(RSA_SIGN, kpg.generateKeyPair(), when);
        PGPKeyPair rsakpEnc =  new BcPGPKeyPair(RSA_ENCRYPT, kpg.generateKeyPair(), when);
        PGPSignatureSubpacketGenerator signhashgen =  new PGPSignatureSubpacketGenerator();

        signhashgen.setKeyFlags (
                false,
                KeyFlags.SIGN_DATA		|
                        KeyFlags.CERTIFY_OTHER	)
        ;

        signhashgen.setPreferredSymmetricAlgorithms(false, new int[] {
                SymmetricKeyAlgorithmTags.CAST5,
                SymmetricKeyAlgorithmTags.AES_256,
                SymmetricKeyAlgorithmTags.AES_192,
                SymmetricKeyAlgorithmTags.TWOFISH,
                SymmetricKeyAlgorithmTags.AES_128	})
        ;

        signhashgen.setPreferredHashAlgorithms(false, new int[] {
                HashAlgorithmTags.SHA256,
                HashAlgorithmTags.SHA1,
                HashAlgorithmTags.SHA384,
                HashAlgorithmTags.SHA512,
                HashAlgorithmTags.SHA224   })
        ;

        signhashgen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
        PGPSignatureSubpacketGenerator enchashgen = new PGPSignatureSubpacketGenerator();
        enchashgen.setKeyFlags(
                false,
                KeyFlags.ENCRYPT_COMMS		|
                        KeyFlags.ENCRYPT_STORAGE	)
        ;

        PGPDigestCalculator sha256Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);
        PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);

        PBESecretKeyEncryptor pske = (new BcPBESecretKeyEncryptorBuilder(CAST5, sha256Calc, s2kcount)).build(pass);

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                rsakpSign,
                id,
                sha1Calc,
                signhashgen.generate(),
                null,
                new BcPGPContentSignerBuilder(
                        rsakpSign.getPublicKey().getAlgorithm(),
                        HashAlgorithmTags.SHA1),
                pske)
                ;

        keyRingGen.addSubKey(rsakpEnc, enchashgen.generate(), null);
        return keyRingGen;
    }

}