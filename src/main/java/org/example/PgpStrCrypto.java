package org.example;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.paint.Color;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.example.crypto.PgpFileHelper;
import org.example.crypto.PgpHelper;
import org.example.crypto.PgpStringHelper;
import org.example.crypto.RsaUtil;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.Iterator;

public class PgpStrCrypto {

    @FXML
    public TextArea textareaPgpStrEncrypt;
    public TextArea textareaPgpStrEncryptOutput;
    public Label LabelPgpStrEncrypt;

    public TextArea textareaPgpStrDecrypt;
    public TextArea textareaPgpStrDecryptOutput;
    public Label LabelPgpStrDecrypt;

    @FXML
    private void encryptPgpStr(){
        if(textareaPgpStrEncrypt.getText().isEmpty()){
            LabelPgpStrEncrypt.setTextFill(Color.color(1,0,0));
            LabelPgpStrEncrypt.setText("Please insert your text !");
        } else {
            try {
                System.out.println("input Text : " + textareaPgpStrEncrypt.getText());
                String pgpEncryptedStr = encryptPgpString(textareaPgpStrEncrypt.getText());
                textareaPgpStrEncryptOutput.setText(pgpEncryptedStr);
                System.out.println(pgpEncryptedStr);

                LabelPgpStrEncrypt.setTextFill(Color.color(0,0,1));
                LabelPgpStrEncrypt.setText("PGP String encrypt successfully.");
            } catch (Exception e){
                System.out.println("Error in PGP String Encryption : " + e.getMessage());
            }
        }
    }

    @FXML
    private void decryptPgpStr(){
        if(textareaPgpStrDecrypt.getText().isEmpty()){
            LabelPgpStrDecrypt.setTextFill(Color.color(1,0,0));
            LabelPgpStrDecrypt.setText("Please insert your text !");
        } else {
            try {
                String pgpDecryptedStr = decryptPgpString(textareaPgpStrDecrypt.getText());
                textareaPgpStrDecryptOutput.setText(pgpDecryptedStr);

                LabelPgpStrDecrypt.setTextFill(Color.color(0,0,1));
                LabelPgpStrDecrypt.setText("PGP String decrypt successfully.");
            } catch (Exception e){
                System.out.println("Error in PGP String Decryption : " + e.getMessage());
            }
        }
    }

    @FXML
    private void pgpStrBack() throws IOException {
        System.out.println("Going back to main");
        App.setRoot("main");
    }


    private String encryptPgpStringTest(String inputText) throws URISyntaxException, IOException, PGPException {

        inputText = "payload    header      msgId     Idf7d88d7fe0d54e9899b7b268bea05ec9   orgId     INS1000001  msgId     Idf7d88d7fe0d54e9899b7b268bea05ec9   orgId     INS1000001 vmsgId     Idf7d88d7fe0d54e9899b7b268bea05ec9   orgId     INS1000001 msgId     Idf7d88d7fe0d54e9899b7b268bea05ec9   orgId     INS1000001 msgId     Idf7d88d7fe0d54e9899b7b268bea05ec9   orgId     INS1000001 msgId     Idf7d88d7fe0d54e9899b7b268bea05ec9   orgId     INS1000001   timeStamp     2020-12-27T12 06 05 191    data      message      requestID     2bda2d0821aa47b0ab61ef1136bcf63e   updateType     T   claimNo     M880730    tDataSet        identifier     DOC1     type     INVOICE_SGH     description     Invoice     documentLevelField      piiDataSet       PatientName          PatientNRIC     @SID1000     InvoiceAddresse     @SID1001     InvoiceAddress     @SID1002     TaxInvNo     @SID1003       txnDataSet       HospitalName     Singapore General Hospital     HospitalAddress     Outram Road  Singapore 169608 Tel  6222 3322     DoctorName          DocumentType     TAX INVOICE     BillType     ORIGINAL     BillSettlement          BillDate     16-Apr-2020     VisitDate     16-Apr-2020     TotalPage     1     SubmittedPage     1     TotalDueAmount             tableLevelFields       LineItem       BillRefNo     6820000007L0001-01     Heading     SUBSIDISED DRUGS     ServiceCode     CDMSTD     Description     PROFESSIONAL FEES - DOCTOR COLECALCIFEROL*(VIT D3) 1000IU TAB     Quantity     180     Amount     27.00       BillRefNo     6820000007L0001-01     Heading     SUBSIDISED DRUGS     ServiceCode     CDMSTD     Description     PROFESSIONAL FEES - DOCTOR CALCIUM CARB 450MG  VITAMIN D 200 U TABLET     Quantity     180     Amount     9.00         GovSubsidies       BillRefNo     6820000007L0001-01     Heading     SUBSIDISED DRUGS     BeforeSubsidies     36.00     TypeOfSubsidies     Government Subsidy     AmountOfSubsidies     -27.00     AfterSubsidies     6.75       BillRefNo     6820000007L0001-01     Heading     SUBSIDISED DRUGS     BeforeSubsidies     36.00     TypeOfSubsidies     Government Subsidy for Merdeka Generation (additional 25% off)     AmountOfSubsidies     -2.25     AfterSubsidies     6.75         BillGSTPayable       BillRefNo     6820000007L0001-01     VisitLocation     GVLMDS / GMBBO / END SUBSIDISED     GSTIndicator     7%     BeforeGST     6.75     AddGST     0.47     AfterGST     7.22     LessGST     -0.47     NetAmountPayable     6.75         PaymentAmount       PayerName     @SID1004     PaymentDate     16-Apr-2020     PaymentAmt     6.75       PayerName     @SID1005     PaymentDate          PaymentAmt     0.00         MediSave       HolderName     @SID1006     AccountNo     @SID1007     AmountDeducted     5.74     EstimatedAmount     1.01     HRN     682020012305c CDMM81         AmountPayable       PayerAmountPayable     @SID1008     AmountPayable     6.75       PayerAmountPayable     @SID1009     AmountPayable     0.00         RoundingAdjustment       PayerAdjustmentBeforePayable          AmountAdjustmentBeforePayable          PayerAdjustmentAfterPayable          AmountAdjustmentAfterPayable              Due       DueFromPayer     @SID1010     DueAmount     0.00       DueFromPayer     @SID1011     DueAmount     0.00          ";

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InputStream stream = new ByteArrayInputStream(inputText.getBytes(StandardCharsets.UTF_8));

        URL resPgpPublicKey = getClass().getClassLoader().getResource("client_public.txt");
        File filePgpPublicKey = Paths.get(resPgpPublicKey.toURI()).toFile();
        System.out.println("base64secret txt file path : " + filePgpPublicKey.getAbsolutePath());

        URL resPgpPrivateKey = getClass().getClassLoader().getResource("vendor_private.txt");
        File filePgpPrivateKey = Paths.get(resPgpPrivateKey.toURI()).toFile();
        System.out.println("base64secret txt file path : " + filePgpPrivateKey.getAbsolutePath());

        String extPgpPublicKey = FileUtils.readFileToString(filePgpPublicKey, "UTF-8");
        String pgpPrivateKey = FileUtils.readFileToString(filePgpPrivateKey, "UTF-8");
        String pgpPassword = "passw0rd";

        InputStream pubIn = new ByteArrayInputStream(extPgpPublicKey.getBytes(StandardCharsets.UTF_8));
        InputStream keyIn = new ByteArrayInputStream(pgpPrivateKey.getBytes(StandardCharsets.UTF_8));

        PGPSecretKey secretKey = PgpHelper.readSecretKey(keyIn);

        PgpHelper.encryptStream(out, PgpHelper.readPublicKey(
                pubIn), secretKey, stream, pgpPassword);

        return(new String(out.toByteArray()));
    }


    private String encryptPgpString(String inputText) throws URISyntaxException, IOException, PGPException {

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InputStream stream = new ByteArrayInputStream(inputText.getBytes(StandardCharsets.UTF_8));

        URL resPgpPublicKey = getClass().getClassLoader().getResource("client_public.txt");
        File filePgpPublicKey = Paths.get(resPgpPublicKey.toURI()).toFile();
        System.out.println("base64secret txt file path : " + filePgpPublicKey.getAbsolutePath());

        URL resPgpPrivateKey = getClass().getClassLoader().getResource("vendor_private.txt");
        File filePgpPrivateKey = Paths.get(resPgpPrivateKey.toURI()).toFile();
        System.out.println("base64secret txt file path : " + filePgpPrivateKey.getAbsolutePath());

        String extPgpPublicKey = FileUtils.readFileToString(filePgpPublicKey, "UTF-8");
        String pgpPrivateKey = FileUtils.readFileToString(filePgpPrivateKey, "UTF-8");
        String pgpPassword = "passw0rd";

        InputStream pubIn = new ByteArrayInputStream(extPgpPublicKey.getBytes(StandardCharsets.UTF_8));
        InputStream keyIn = new ByteArrayInputStream(pgpPrivateKey.getBytes(StandardCharsets.UTF_8));

        //ObjectMapper CBOR_MAPPER = createMapper( new CBORFactory() );
        //byte[] jsonByte = CBOR_MAPPER.writeValueAsBytes(sampleJson);
        String encryptedOutput = PgpStringHelper.encrypt(inputText.getBytes(StandardCharsets.UTF_8), PgpHelper.readPublicKey(pubIn));

        //PGPSecretKey secretKey = PgpHelper.readSecretKey(keyIn);

//        PgpHelper.encryptStream(out, PgpHelper.readPublicKey(
//                pubIn), secretKey, stream, pgpPassword);

        return encryptedOutput;
    }

    private ObjectMapper createMapper( JsonFactory factory )
    {
        ObjectMapper mapper = new ObjectMapper( factory );

        mapper.setVisibility( PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY );

        return mapper;
    }

    private String decryptPgpString(String inputCipherText) throws URISyntaxException, IOException, PGPException {

//        inputCipherText = "-----BEGIN PGP MESSAGE-----\n" +
//                "Version: BCPG v1.52\n" +
//                "\n" +
//                "hQEMA/EI1rq27SGDAgf+Luzp9Mxu3CqWzbqR+Qtyh5cs+p9jArV8HW3IVyGDsrxh\n" +
//                "Coblrf0NdpwUMO+ruY7W5yOmdKJbnHHJ/4MdaYUqCSWWhLW6kDz9OyXwiB5T3ADf\n" +
//                "gN6Lk6jxqqeFpOCFKQwm5MFsNksU564vBr6HfCCrJfJU3p50Aa+0xPTxtXj4/xAy\n" +
//                "/ahEBHk+qjAClaNUYh+NqUJUvYcIdDYD3KIpAiGAujn2XUN8H3gXbI9zw7e2JirY\n" +
//                "/ZPv8IIkq63TIssjYO+gKmA+mFfLE4Drz2nsp2PNqv5EVQHVeg6VCdGk7FcIieVj\n" +
//                "XoaiYip+x2QDakZj8uStbuDU8nbYrtcIWkQ6KGIMCtLCmgEViaPakEDx21ZIuLsr\n" +
//                "rdeIQawUG0j1AfSbmotgQL7OaljwE9lNEDmhk2PoSR4WNkAjGuzoHsCc6+c6RCVh\n" +
//                "R0wuRFQTwRRNLPYpJEFpFIEYjm1eHS8J89ZTKvqznJAgqnvqKkm0vEHnjOpZt/G+\n" +
//                "FFSQ8vRB0VSM4uLDXnXzwQ67iLrZrzlMeCq7ElEwuX29iDX7CubF8cf7ujHNaQ+/\n" +
//                "nbok3itggHDkgAZl3Yt6xxyqrkY7YDDGLzr0egOO34VqOTRTH93785cEaN5bY25D\n" +
//                "p3PDk9s1mw3cjfn3mjJwwQ3rt24c7hgOjxB2xPb+bvIp7WdsYmnhbRi/iT9iiauy\n" +
//                "HaX1M/KCAWGQ69yy1YufNn2xzLUCPP5zx6p3D0HxPbFgO6lsjrbSPjDNLrBL6c5b\n" +
//                "/uGU0Z3U6Ti0bPII6oZxE2przjHv7YebG3Vd2BbbZ3u5oBja6b2kcaQ4cqYUn4ur\n" +
//                "A7LP+k77CzvDO867UttyW4wS0EHcy3fn488NuO1BfZHpoWSGcVFTfx3rsTSr2LdH\n" +
//                "xkdQFcqtBlB6/rpf/vymaFot+NozjV5iTz6TWWyjC5O+xJC95hrfp082Q+T3auSm\n" +
//                "ApcRmPxQVKt5UlqiBTHSO3M5h+znIjUOen0C+SIV0WRmOQxrKfug7mwgG58T90md\n" +
//                "XwFDr0r67JmHpQbXWUC3eGNhxb6eZZiTCCqdjyFQkJHOrXgKAPs+qT2N852BHnDs\n" +
//                "JXqGwl+w/RClttrxFBc5ZtdkzhkJ0yyc6D7j8NJhWMdJiKfEoRI2hrTPkLrnIGxC\n" +
//                "2Xm7m4KZMU3kTF0oplilEMXXna2p3C6oyK4iOhWTbvJ6Goj4MXDqQBBBknQNFzsD\n" +
//                "3mN+c4Vias4vtQ8duHmn1axu3YiE/VCw3hMdnZsvwznO+VS8T+f352zcqsCEJDY5\n" +
//                "hLlHP3qaYRqLvNAEAC0ekEhterHql4NW1dMaA4DcBonNYZCGWjgSswRnCQr4LEHr\n" +
//                "qo9mkcIO8cJMJBSJjSeuPm57wPF3X9juqejt+kRsyZburr8C56OgRzaZMwYM2T/N\n" +
//                "PbkCc9KOdv3pJ5aBB5JDSpRFLsKUniRWN2s6AG3fX46O8Osdxb4LAe5ZBdxGpg6R\n" +
//                "dtDgJwK+4xq+0GDu6bQ0a2HF9LhtXJj+F78IyA==\n" +
//                "=hCQx\n" +
//                "-----END PGP MESSAGE-----";

        String decrypTxt = "";
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ByteArrayInputStream bais = new ByteArrayInputStream(inputCipherText.trim().getBytes(StandardCharsets.UTF_8));

        URL resPgpPublicKey = getClass().getClassLoader().getResource("vendor_public.txt");
        File filePgpPublicKey = Paths.get(resPgpPublicKey.toURI()).toFile();
        System.out.println("base64secret txt file path : " + filePgpPublicKey.getAbsolutePath());

        URL resExtPgpPrivateKey = getClass().getClassLoader().getResource("client_private.txt");
        File fileExtPgpPrivateKey = Paths.get(resExtPgpPrivateKey.toURI()).toFile();
        System.out.println("base64secret txt file path : " + fileExtPgpPrivateKey.getAbsolutePath());

        String pgpPublicKey = FileUtils.readFileToString(filePgpPublicKey, "UTF-8");
        String extpgpPrivateKey = FileUtils.readFileToString(fileExtPgpPrivateKey, "UTF-8");
        String pgpPassword = "passw0rd";

        InputStream pubIn = new ByteArrayInputStream(pgpPublicKey.getBytes(StandardCharsets.UTF_8));
        InputStream keyIn = new ByteArrayInputStream(extpgpPrivateKey.getBytes(StandardCharsets.UTF_8));

        // Convert cipherText inputstream to outputstream:
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        InputStream tempIs = new ByteArrayInputStream(inputCipherText.getBytes(StandardCharsets.UTF_8));
        IOUtils.copy( tempIs, bos );

        PGPPrivateKey sKey = PgpStringHelper.getPgpStringPrivateKey(bais, keyIn, pgpPassword);

        byte[] plainContent = PgpStringHelper.decrypt(bos.toByteArray(), sKey);

        System.out.println(new String(plainContent));

        return (new String(plainContent));
    }
}
