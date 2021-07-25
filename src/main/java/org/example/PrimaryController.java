package org.example;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

import javafx.fxml.FXML;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.example.crypto.PgpFileHelper;
import org.example.crypto.PgpHelper;

public class PrimaryController {

    @FXML
    private void switchToSecondary() throws IOException, PGPException, URISyntaxException {
        System.out.println("hello world");

        //generatePGPKeys();
        //encryptPgpFile();
        pgpEncryptStr();

        App.setRoot("secondary");
    }

    public void pgpEncryptStr() throws URISyntaxException, IOException {

        URL resPgpPublicKey = getClass().getClassLoader().getResource("client_public.txt");
        File filePgpPublicKey = Paths.get(resPgpPublicKey.toURI()).toFile();
        System.out.println("base64secret txt file path : " + filePgpPublicKey.getAbsolutePath());

        URL resPgpPrivateKey = getClass().getClassLoader().getResource("vendor_private.txt");
        File filePgpPrivateKey = Paths.get(resPgpPrivateKey.toURI()).toFile();
        System.out.println("base64secret txt file path : " + filePgpPrivateKey.getAbsolutePath());

        String extPgpPublicKey = FileUtils.readFileToString(filePgpPublicKey, "UTF-8");
        String pgpPrivateKey = FileUtils.readFileToString(filePgpPrivateKey, "UTF-8");
        String pgpPassword = "passw0rd";

        String inputText = "{23\n\t\nd\nwdfvfve\"ververv\"ef}";

        String inputText2 = "{\n" +
                "  \"header\" : {\n" +
                "    \"msgId\" : \"Idd68c75d79abe4c1fafc12ef5c2716d0f\",\n" +
                "    \"orgId\" : \"INS1000001\",\n" +
                "    \"timeStamp\" : \"2020-12-23T13:39:41:734eiorjfiovervioerf" +
                "  },\n" +
                "  \"data\" : {\n" +
                "    \"message\" : {\n" +
                "      \"requestID\" : \"2bda2d0821aa47b0ab61ef1136bcf63e\",\n" +
                "      \"updateType\" : \"P\",\n" +
                "      \"claimNo\" : \"M880730\"\n" +
                "    },\n" +
                "    \"pDataSet\" : {\n" +
                "      \"sid\" : \"@SID1011\",\n" +
                "      \"pData\" : \"cq/Fdrl9AhkRYIXA/K9a6avTb+BtCGjSl6pGQ9BoCE9P5YIdryBWjl76WslM0iQiTp58sxNTp9UkmUeeiHUPs7CTquy13Y7fK0oRbEQZMKPJKUle/KDZ9fNJfCDYalAvuiFsQFEgp9HL5IbsG98Kdcmy/Q+6i+HyI/mTsgUrt+hjLmldRtpCC7dZYGVfAACvC2bwKu35wp7QrDrDL5CzJo1F3iWrwhJN3BlGYVY1LjQESDoX6q4k1pEfB9UO5mnT1VYK3nXYutbHJloCGjY2hSw33XS+wIK96ai7+p6MZfn8h0EFxNOG0IyBBMtdOSZQmZNJAOHJv0L9VrkNPzAc6w==\",\n" +
                "      \"pDataHash\" : \"LJ9HvSqTTFsiOcN1NxfrFdzajcYHftpGosZ1o47xAuOSE9IYjE6GeUpL9G5SzFthxMhvbOYmhc0f/MGlBKKxD0mUldvP1H8UsVn5wZlvdmu5E/SKpwCtC/RzP4DAfWE+FmtMGnQePjLmJzhd8sIeX+Whdssto8Xa/RMtOWLafmBjhkymvviRxxQLq9WNXQcU+/ilPKEh18tqW8MgNw8OtNk+yRpRqqyIlq9/IKYScTky3W0mS3AQcycGdy6TZMU1O/IYDuYtgvzkG4UGW5YrlcShFyfEHscCoL8iFduxlggwiTRcKp4wCUw6GWq3Ryx9XamWMQ/8z70eyt8BwWoCfA==\",\n" +
                "      \"count\" : \"12/12\"\n" +
                "    }\n" +
                "  }\n" +
                "}";

        String encrypTxt = "";
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        //convert the data to input stream
        //LOGGER.info("payload: {}", pgpMapper.getPayload());
        InputStream stream = new ByteArrayInputStream(inputText2.getBytes(StandardCharsets.UTF_8));

        try {
            try (InputStream pubIn = new ByteArrayInputStream(extPgpPublicKey.getBytes(StandardCharsets.UTF_8));
                 InputStream keyIn = new ByteArrayInputStream(pgpPrivateKey.getBytes(StandardCharsets.UTF_8))) {
                PGPSecretKey secretKey = PgpHelper.readSecretKey(keyIn);
                PgpHelper.encryptStream(out, PgpHelper.readPublicKey(
                        pubIn), secretKey, stream, pgpPassword);
                encrypTxt = new String(out.toByteArray());
            }
        }catch (IOException ioe){
            //dataUpdateAdaptor.updateErrorInternal("Non-Applicable","ER02", "PGP Encryption String Error: " + ioe.toString());
            //LOGGER.error(ioe);
        }catch (PGPException pgpEx){
            //LOGGER.error(pgpEx);
        }
//        finally {
//            //close all the stream
//            try {
//                out.close();
//            }catch(IOException ignore){LOGGER.error(ignore);}
//        }

        System.out.println(encrypTxt);

    }

    private void encryptPgpFile() throws URISyntaxException, IOException {
        byte[] encryptBytes = null;
        boolean needSign = true;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        URL resTargetFile = getClass().getClassLoader().getResource("test.pdf");
        File file = Paths.get(resTargetFile.toURI()).toFile();
        System.out.println("base64secret txt file path : " + file.getAbsolutePath());

        URL resPgpPublicKey = getClass().getClassLoader().getResource("client_public.txt");
        File filePgpPublicKey = Paths.get(resPgpPublicKey.toURI()).toFile();
        System.out.println("base64secret txt file path : " + filePgpPublicKey.getAbsolutePath());

        URL resPgpPrivateKey = getClass().getClassLoader().getResource("vendor_private.txt");
        File filePgpPrivateKey = Paths.get(resPgpPrivateKey.toURI()).toFile();
        System.out.println("base64secret txt file path : " + filePgpPrivateKey.getAbsolutePath());

        File targetFile = new File("encrypted.pdf");
        File targetFileNew = new File("encrypted_new.pdf");

        String extPgpPublicKey = FileUtils.readFileToString(filePgpPublicKey, "UTF-8");
        String pgpPrivateKey = FileUtils.readFileToString(filePgpPrivateKey, "UTF-8");
        String pgpPassword = "passw0rd";

        try {
            try (InputStream pubIn = new ByteArrayInputStream(extPgpPublicKey.getBytes());
                 InputStream keyIn = new ByteArrayInputStream(pgpPrivateKey.getBytes());
            ) {
                InputStream initialStream = new FileInputStream(file);
                byte[] buffer = new byte[initialStream.available()];
                initialStream.read(buffer);
                try (OutputStream outStream = new FileOutputStream(targetFile)) {
                    outStream.write(buffer);
                }
                PGPPublicKey publicKey =  PgpHelper.readPublicKey(
                        pubIn);
                if(needSign) {
                    //find secret key
                    PGPSecretKey secretKey = PgpHelper.readSecretKey(keyIn);
                    //(OutputStream out, String fileName, PGPPublicKey publicKey, PGPSecretKey secretKey, String password, boolean armor, boolean withIntegrityCheck)
                    PgpFileHelper.signEncryptFile(out,targetFile.getAbsolutePath(),publicKey,secretKey,pgpPassword,true,true);
                }else{
                    PgpFileHelper.encryptFile(out,targetFile.getAbsolutePath(),publicKey, true, true);
                }
                encryptBytes = out.toByteArray();
                }
        }catch (Exception e ){
            System.out.println(e.getMessage());
        }

        try (FileOutputStream fileOutputStream = new FileOutputStream(targetFileNew)){
            fileOutputStream.write(encryptBytes);
            System.out.println("File writeup success...");
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
