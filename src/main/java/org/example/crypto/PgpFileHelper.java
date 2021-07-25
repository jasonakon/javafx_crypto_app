package org.example.crypto;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import static org.bouncycastle.bcpg.CompressionAlgorithmTags.ZIP;
import static org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.CAST5;

public class PgpFileHelper {

    private static final int BUFFER_SIZE = 1 << 16; // should always be power of 2

    private PgpFileHelper() {
        throw new IllegalStateException("Utility class");
    }

    public static void encryptFile(OutputStream out, String fileName, PGPPublicKey encKey, boolean armor,
                                   boolean withIntegrityCheck) throws IOException,  PGPException {
        Security.addProvider(new BouncyCastleProvider());

        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(ZIP);
        PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));
        comData.close();
        JcePGPDataEncryptorBuilder dataEncryptor = new JcePGPDataEncryptorBuilder(CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC");

        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptor);
        JcePublicKeyKeyEncryptionMethodGenerator methodGenerator = new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());

        encryptedDataGenerator.addMethod(methodGenerator);


        byte[] bytes = bOut.toByteArray();
        try(
        OutputStream cOut = encryptedDataGenerator.open(out, new byte[BUFFER_SIZE]);

        ) {
            cOut.write(bytes);
            encryptedDataGenerator.close();
        }finally{
            out.close();
            bOut.close();
        }
    }
    public static void writeToFile(byte[] data, String filename){
        try(FileOutputStream out = new FileOutputStream(filename)){
            out.write(data);
        }catch(IOException e){
            System.out.println(e.getMessage());
        }

    }

        public static void decryptFile(InputStream in, OutputStream out, InputStream privKey, InputStream pubKey, char[] passwd) throws IOException, PGPException {

        Security.addProvider(new BouncyCastleProvider());

        in = PGPUtil.getDecoderStream(in);
        PGPObjectFactory pgpF = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();
        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof  PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        //
        // find the secret key
        //
        Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;

        while (sKey == null && it.hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) it.next();
            sKey = PgpHelper.findPrivateKey(privKey, pbe.getKeyID(), passwd);
        }

        if (sKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        PublicKeyDataDecryptorFactory b = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").setContentProvider("BC").build(sKey);


        InputStream clear = pbe.getDataStream(b);
        PGPObjectFactory plainFact = new PGPObjectFactory(PGPUtil.getDecoderStream(clear), new BcKeyFingerprintCalculator());
        PGPOnePassSignatureList onePassSignatureList = null;
        PGPSignatureList signatureList = null;

        Object message = plainFact.nextObject();
        ByteArrayOutputStream actualOutput = new ByteArrayOutputStream();
        while(message!=null) {
            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                plainFact = new PGPObjectFactory(PGPUtil.getDecoderStream(cData.getDataStream()), null);

                message = plainFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;
                InputStream unc = ld.getInputStream();
                int ch;
                while ((ch = unc.read()) >= 0) {
                    out.write(ch);
                }
                Streams.pipeAll(((PGPLiteralData) message).getInputStream(), actualOutput);
            } else if (message instanceof PGPOnePassSignatureList) {
                onePassSignatureList = (PGPOnePassSignatureList) message;

            } else if (message instanceof PGPSignatureList) {
                signatureList = (PGPSignatureList) message;
            } else {
                throw new PGPException("Message is not a simple encrypted file - type unknown.");
            }
            message = plainFact.nextObject();
        }

        if(onePassSignatureList!=null && signatureList!=null) {
            boolean isVerified = verifySignature(onePassSignatureList,pubKey,new ByteArrayOutputStream().toByteArray(),signatureList);
            System.out.println("isVerified: " +isVerified);
        }

        if (pbe.isIntegrityProtected()&&!pbe.verify()) {
                throw new PGPException("Message failed integrity check");
        }
        actualOutput.close();
    }

    public static boolean verifySignature(PGPOnePassSignatureList onePassSignatureList, InputStream publicKeyIn, byte[] output, PGPSignatureList signatureList)throws IOException, PGPException{

        boolean isVerified = false;
        for (int i = 0; i < onePassSignatureList.size(); i++) {
            PGPOnePassSignature ops = onePassSignatureList.get(0);
            PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicKeyIn),new BcKeyFingerprintCalculator());
            PGPPublicKey publicKey = pgpRing.getPublicKey(ops.getKeyID());
            if (publicKey != null) {
                ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
                ops.update(output);
                PGPSignature signature = signatureList.get(i);
                if (ops.verify(signature)) {
                    return true;
                }
            }
        }
        return isVerified;
    }

    public static void signEncryptFile(OutputStream out, String fileName, PGPPublicKey publicKey,
                                       PGPSecretKey secretKey, String password, boolean armor, boolean withIntegrityCheck) throws IOException, PGPException{

        // Initialize Bouncy Castle security provider
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        JcePGPDataEncryptorBuilder dataEncryptor = new JcePGPDataEncryptorBuilder(CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC");

        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptor);
        JcePublicKeyKeyEncryptionMethodGenerator methodGenerator = new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());
        encryptedDataGenerator.addMethod( methodGenerator);
        // Initialize compressed data generator
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(ZIP);
        try(
            OutputStream encryptedOut = encryptedDataGenerator.open(out, new byte[BUFFER_SIZE]);
            OutputStream compressedOut = compressedDataGenerator.open(encryptedOut, new byte[BUFFER_SIZE]);
        ) {
            // Initialize signature generator
            PGPPrivateKey privateKey = PgpHelper.findPrivateKey(secretKey, password.toCharArray());

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

            // Initialize literal data generator
            PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
            try(
            OutputStream literalOut = literalDataGenerator.open(compressedOut, PGPLiteralData.BINARY, fileName, new Date(),
                    new byte[BUFFER_SIZE]);

            // Main loop - read the "in" stream, compress, encrypt and write to the "out" stream
            FileInputStream in = new FileInputStream(fileName);
            ) {
                byte[] buf = new byte[BUFFER_SIZE];
                int len;
                while ((len = in.read(buf)) > 0) {
                    literalOut.write(buf, 0, len);
                    signatureGenerator.update(buf, 0, len);
                }

            }
            literalDataGenerator.close();
            // Generate the signature, compress, encrypt and write to the "out" stream
            signatureGenerator.generate().encode(compressedOut);
            compressedDataGenerator.close();
            encryptedDataGenerator.close();
        }finally{
            if (armor) {
                out.close();
            }

        }

    }

}
