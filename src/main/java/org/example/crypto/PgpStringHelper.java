package org.example.crypto;

import java.io.*;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

public class PgpStringHelper {

    public static byte[] decrypt( byte encData[], PGPPrivateKey privateKey ) throws PGPException, IOException
    {
        Security.addProvider(new BouncyCastleProvider());

        PGPPublicKeyEncryptedData pgpEncData = getPGPEncryptedData( encData );

        InputStream is = getInputStream( privateKey, pgpEncData );

        // IMPORTANT: pipe() should be before verify(). Otherwise we get "java.io.EOFException: Unexpected end of ZIP
        // input stream".
        byte data[] = pipe( is );

        if ( !pgpEncData.verify() )
        {
            throw new PGPDataValidationException( "Data integrity check failed" );
        }

        return data;
    }

    public static String encrypt( byte data[], PGPPublicKey publicKey ) throws IOException, PGPException
    {
        Security.addProvider(new BouncyCastleProvider());

        byte[] compressedData = compress( data );

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        ArmoredOutputStream aos = new ArmoredOutputStream( bos );

        OutputStream encOut = getEncryptedGenerator( publicKey ).open( aos, compressedData.length );

        encOut.write( compressedData );

        encOut.close();

        aos.close();

        return (new String(bos.toByteArray()));
    }

    public static PGPPrivateKey getPgpStringPrivateKey(InputStream inputCipherIs, InputStream privateKeyIs, String pgpPassword ) throws IOException, PGPException {
        InputStream is = PGPUtil.getDecoderStream(inputCipherIs);
        PGPObjectFactory pgpF = new PGPObjectFactory(is, new BcKeyFingerprintCalculator());
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
            sKey = PgpHelper.findPrivateKey(privateKeyIs, pbe.getKeyID(), pgpPassword.toCharArray());
        }

        return sKey;
    }


    private static PGPEncryptedDataGenerator getEncryptedGenerator( PGPPublicKey publicKey )
    {
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder( PGPEncryptedData.CAST5 ).setWithIntegrityPacket( true )
                        .setSecureRandom( new SecureRandom() )
                        .setProvider( "BC" ) );

        encGen.addMethod( new JcePublicKeyKeyEncryptionMethodGenerator( publicKey ).setProvider( "BC" ) );

        return encGen;
    }


    private static byte[] compress( byte data[] ) throws IOException
    {
        PGPCompressedDataGenerator compressGen = new PGPCompressedDataGenerator( CompressionAlgorithmTags.ZIP );

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        OutputStream compressOut = compressGen.open( bos );

        OutputStream os = new PGPLiteralDataGenerator().open( compressOut, PGPLiteralData.BINARY, "", data.length, new Date() );

        os.write( data );

        os.close();

        compressGen.close();

        return bos.toByteArray();
    }

    private static byte[] pipe( InputStream is ) throws IOException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        Streams.pipeAll( is, bos );

        bos.close();

        return bos.toByteArray();
    }


    private static InputStream getInputStream( PGPPrivateKey privateKey, PGPPublicKeyEncryptedData pgpEncData )
            throws PGPException, IOException
    {
        InputStream is = pgpEncData.getDataStream( new JcePublicKeyDataDecryptorFactoryBuilder().setProvider( "BC" ).setContentProvider("BC").build( privateKey ) );

        JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory( is );

        Object message = objectFactory.nextObject();

        PGPCompressedData compressedData = ( PGPCompressedData ) message;

        JcaPGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory( compressedData.getDataStream() );

        PGPLiteralData literalData = ( PGPLiteralData ) pgpObjectFactory.nextObject();

        return literalData.getInputStream();
    }


    private static PGPPublicKeyEncryptedData getPGPEncryptedData( byte data[] ) throws IOException
    {
        InputStream in = PGPUtil.getDecoderStream( new ByteArrayInputStream( data ) );

        JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory( in );

        PGPEncryptedDataList encryptedDataList = ( PGPEncryptedDataList ) objectFactory.nextObject();

        Iterator it = encryptedDataList.getEncryptedDataObjects();

        return ( PGPPublicKeyEncryptedData ) it.next();
    }
}
