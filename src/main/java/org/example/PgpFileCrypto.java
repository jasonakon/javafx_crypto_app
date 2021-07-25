package org.example;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.paint.Color;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.example.crypto.PgpFileHelper;
import org.example.crypto.PgpHelper;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

public class PgpFileCrypto {

    private Stage stage;
    private File selectedRawFile = null;
    private File selectedEncryptedFile = null;

    @FXML
    public Label LabelPgpFileEncrypt;
    public Label LabelPgpFileDecrypt;
    public Button butSelectPgpFileraw;

    public TextArea textAreaPgpPublicKey;
    public TextArea textAreaPgpPrivateKey;
    public TextField textFieldPgpPassword;

    public TextArea textAreaGenPgpPublicKeyOutput;
    public TextArea textAreaGenPgpPrivateKeyOutput;
    public TextField textFieldGenPgpPasswordInput;
    public Label labelGenPgpKey;

    public void setStage(Stage stage){
        this.stage = stage;
    }

    private enum pgpConfigStatus {
        EMPTY,
        COMPLETE,
        INCOMPLETE
    }

    @FXML
    private void selectEncryptPgpFile(){
        // Get File:
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open raw file");
        selectedRawFile =  fileChooser.showOpenDialog(stage);

        // Update Label Notification:
        LabelPgpFileEncrypt.setTextFill(Color.color(0,0,1));
        LabelPgpFileEncrypt.setText("File selected : " + selectedRawFile.getName());
    }

    @FXML
    private void encryptPgpFile() throws IOException, URISyntaxException {
        if(selectedRawFile == null){
            LabelPgpFileEncrypt.setTextFill(Color.color(1,0,0));
            LabelPgpFileEncrypt.setText("Please select your file !");
        } else {
            if(getConfigStatus().equals(pgpConfigStatus.INCOMPLETE)) {
                LabelPgpFileEncrypt.setTextFill(Color.color(1, 0, 0));
                LabelPgpFileEncrypt.setText("Please complete your configuration");
            } else if(getConfigStatus().equals(pgpConfigStatus.EMPTY)){
                try {
                    encryptPgpFileFunc(selectedRawFile);
                    LabelPgpFileEncrypt.setTextFill(Color.color(0, 1, 0));
                    LabelPgpFileEncrypt.setText("File : " + selectedRawFile.getName() + " is successfully encrypted !");
                } catch (Exception e) {
                    LabelPgpFileEncrypt.setTextFill(Color.color(1, 0, 0));
                    LabelPgpFileEncrypt.setText("File Encryption Failed : " + "File : " + selectedRawFile.getName() + " Error : " + e.getMessage());
                }
            } else if(getConfigStatus().equals(pgpConfigStatus.COMPLETE)){
                try {
                    encryptPgpFileFunc(selectedRawFile,textAreaPgpPublicKey.getText(), textAreaPgpPrivateKey.getText(), textFieldPgpPassword.getText());
                    LabelPgpFileEncrypt.setTextFill(Color.color(0, 1, 0));
                    LabelPgpFileEncrypt.setText("File : " + selectedRawFile.getName() + " is successfully encrypted !");
                } catch (Exception e) {
                    LabelPgpFileEncrypt.setTextFill(Color.color(1, 0, 0));
                    LabelPgpFileEncrypt.setText("File Encryption Failed : " + "File : " + selectedRawFile.getName() + " Error : " + e.getMessage());
                }
            }
        }
    }

    @FXML
    private void selectDecryptPgpFile(){
        // Get File:
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open encrypted file");
        selectedEncryptedFile =  fileChooser.showOpenDialog(stage);

        // Update Label Notification:
        LabelPgpFileDecrypt.setTextFill(Color.color(0,0,1));
        LabelPgpFileDecrypt.setText("File selected : " + selectedEncryptedFile.getName());
    }

    @FXML
    private void decryptPgpFile() throws IOException, URISyntaxException {
        if(selectedEncryptedFile == null){
            LabelPgpFileDecrypt.setTextFill(Color.color(1,0,0));
            LabelPgpFileDecrypt.setText("Please select your file !");
        } else {
            if(getConfigStatus().equals(pgpConfigStatus.INCOMPLETE)) {
                LabelPgpFileDecrypt.setTextFill(Color.color(1, 0, 0));
                LabelPgpFileDecrypt.setText("Please complete your configuration");
            } else if(getConfigStatus().equals(pgpConfigStatus.EMPTY)){
                try {
                    decryptPgpFileFunc(selectedEncryptedFile);
                    LabelPgpFileDecrypt.setTextFill(Color.color(0, 1, 0));
                    LabelPgpFileDecrypt.setText("File : " + selectedEncryptedFile.getName() + " is successfully decrypted !");
                } catch (Exception e) {
                    LabelPgpFileDecrypt.setTextFill(Color.color(1, 0, 0));
                    LabelPgpFileDecrypt.setText("File Decryption Failed : " + "File : " + selectedEncryptedFile.getName() + " Error : " + e.getMessage());
                }
            } else if(getConfigStatus().equals(pgpConfigStatus.COMPLETE)){
                try {
                    decryptPgpFileFunc(selectedEncryptedFile, textAreaPgpPublicKey.getText(), textAreaPgpPrivateKey.getText(), textFieldPgpPassword.getText());
                    LabelPgpFileDecrypt.setTextFill(Color.color(0, 1, 0));
                    LabelPgpFileDecrypt.setText("File : " + selectedEncryptedFile.getName() + " is successfully decrypted !");
                } catch (Exception e) {
                    LabelPgpFileDecrypt.setTextFill(Color.color(1, 0, 0));
                    LabelPgpFileDecrypt.setText("File Decryption Failed : " + "File : " + selectedEncryptedFile.getName() + " Error : " + e.getMessage());
                }
            }
        }
    }

    @FXML
    private void generatePgpKey() throws IOException, PGPException {

        if(textFieldGenPgpPasswordInput.getText().isEmpty()){
            labelGenPgpKey.setTextFill(Color.color(1,0,0));
            labelGenPgpKey.setText("Please insert your password !");
        } else {
            // Retrieve all the pgp keys:
            String[] pgpKeyList = getPgpKeyList(textFieldGenPgpPasswordInput.getText());
            textAreaGenPgpPublicKeyOutput.setText(pgpKeyList[0]);
            textAreaGenPgpPrivateKeyOutput.setText(pgpKeyList[1]);

            labelGenPgpKey.setTextFill(Color.color(0,0,1));
            labelGenPgpKey.setText("Pgp key successfully generated.");
        }
    }

    @FXML
    private void pgpFileBack() throws IOException {
        System.out.println("Going back to main");
        App.setRoot("main");
    }

    private String[] getPgpKeyList(String password) throws IOException, PGPException {
        File filePgpPublicKey = new File("pgp_public_key.txt");
        File filePgpPrivateKey = new File("pgp_private_key.txt");

        OutputStream pgpPubOS = new FileOutputStream(filePgpPublicKey);
        OutputStream pgpPrvOS = new FileOutputStream(filePgpPrivateKey);
        PgpHelper.generateKeys(pgpPubOS, pgpPrvOS, password);

        String pgpPublicKey = FileUtils.readFileToString(filePgpPublicKey, "UTF-8");
        String pgpPrivateKey = FileUtils.readFileToString(filePgpPrivateKey, "UTF-8");

        // Key sequence : -> Public Key -> Private Key ->
        String pgpKeyList[] = {pgpPublicKey, pgpPrivateKey};

        return pgpKeyList;
    }

    private pgpConfigStatus getConfigStatus(){
        // Verify if config is empty or not:
        if(textAreaPgpPrivateKey.getText().isEmpty() && textAreaPgpPublicKey.getText().isEmpty() && textFieldPgpPassword.getText().isEmpty()){
            return pgpConfigStatus.EMPTY;
        }

        if(textAreaPgpPrivateKey.getText().isEmpty() || textAreaPgpPublicKey.getText().isEmpty() || textFieldPgpPassword.getText().isEmpty()){
            return pgpConfigStatus.INCOMPLETE;
        }

        return pgpConfigStatus.COMPLETE;
    }

    private void encryptPgpFileFunc(File inputFile, String extPgpPublicKey, String pgpPrivateKey, String pgpPassword){
        byte[] encryptBytes = null;
        boolean needSign = true;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        String targetFileName = inputFile.getName().split("\\.")[0] + "_encrypted." + inputFile.getName().split("\\.")[1];
        File targetFileNew = new File(targetFileName);

        try {
            try (InputStream pubIn = new ByteArrayInputStream(extPgpPublicKey.getBytes());
                 InputStream keyIn = new ByteArrayInputStream(pgpPrivateKey.getBytes());
            ) {
                InputStream initialStream = new FileInputStream(inputFile);
                byte[] buffer = new byte[initialStream.available()];
                initialStream.read(buffer);
                PGPPublicKey publicKey =  PgpHelper.readPublicKey(
                        pubIn);
                if(needSign) {
                    //find secret key
                    PGPSecretKey secretKey = PgpHelper.readSecretKey(keyIn);
                    //(OutputStream out, String fileName, PGPPublicKey publicKey, PGPSecretKey secretKey, String password, boolean armor, boolean withIntegrityCheck)
                    PgpFileHelper.signEncryptFile(out,inputFile.getAbsolutePath(),publicKey,secretKey,pgpPassword,true,true);
                }else{
                    PgpFileHelper.encryptFile(out,inputFile.getAbsolutePath(),publicKey, true, true);
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

    private void encryptPgpFileFunc(File inputFile) throws URISyntaxException, IOException {
        byte[] encryptBytes = null;
        boolean needSign = true;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        //URL resTargetFile = getClass().getClassLoader().getResource("test.pdf");
        //File file = Paths.get(resTargetFile.toURI()).toFile();
        //System.out.println("base64secret txt file path : " + file.getAbsolutePath());
        //File file = inputFile;

        URL resPgpPublicKey = getClass().getClassLoader().getResource("client_public.txt");
        File filePgpPublicKey = Paths.get(resPgpPublicKey.toURI()).toFile();
        System.out.println("base64secret txt file path : " + filePgpPublicKey.getAbsolutePath());

        URL resPgpPrivateKey = getClass().getClassLoader().getResource("vendor_private.txt");
        File filePgpPrivateKey = Paths.get(resPgpPrivateKey.toURI()).toFile();
        System.out.println("base64secret txt file path : " + filePgpPrivateKey.getAbsolutePath());

        String targetFileName = inputFile.getName().split("\\.")[0] + "_encrypted." + inputFile.getName().split("\\.")[1];
        File targetFileNew = new File(targetFileName);

        String extPgpPublicKey = FileUtils.readFileToString(filePgpPublicKey, "UTF-8");
        String pgpPrivateKey = FileUtils.readFileToString(filePgpPrivateKey, "UTF-8");
        String pgpPassword = "passw0rd";

        try {
            try (InputStream pubIn = new ByteArrayInputStream(extPgpPublicKey.getBytes());
                 InputStream keyIn = new ByteArrayInputStream(pgpPrivateKey.getBytes());
            ) {
                InputStream initialStream = new FileInputStream(inputFile);
                byte[] buffer = new byte[initialStream.available()];
                initialStream.read(buffer);
                PGPPublicKey publicKey =  PgpHelper.readPublicKey(
                        pubIn);
                if(needSign) {
                    //find secret key
                    PGPSecretKey secretKey = PgpHelper.readSecretKey(keyIn);
                    //(OutputStream out, String fileName, PGPPublicKey publicKey, PGPSecretKey secretKey, String password, boolean armor, boolean withIntegrityCheck)
                    PgpFileHelper.signEncryptFile(out,inputFile.getAbsolutePath(),publicKey,secretKey,pgpPassword,true,true);
                }else{
                    PgpFileHelper.encryptFile(out,inputFile.getAbsolutePath(),publicKey, true, true);
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

    private void decryptPgpFileFunc(File inputFile, String PgpPublicKey, String pgpExtPrivateKey, String paraphase) throws IOException, PGPException {
        String targetFileName = inputFile.getName().split("\\.")[0] + "_decrypted." + inputFile.getName().split("\\.")[1];
        File decryptedFile = new File(targetFileName);

        byte[] decryptBytes = null;

        InputStream keyIn = new ByteArrayInputStream(pgpExtPrivateKey.getBytes(StandardCharsets.UTF_8));
        InputStream pubKey = new ByteArrayInputStream(PgpPublicKey.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        //convert encrypted message to input stream
        InputStream bais = new ByteArrayInputStream(FileUtils.readFileToByteArray(inputFile));

        PgpFileHelper.decryptFile(bais, baos, keyIn,pubKey, paraphase.toCharArray());
        //return the decrypted message
        decryptBytes =  baos.toByteArray();

        try (FileOutputStream fileOutputStream = new FileOutputStream(decryptedFile)){
            fileOutputStream.write(decryptBytes);
            System.out.println("File decrypted success...");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void decryptPgpFileFunc(File inputFile) throws URISyntaxException, IOException, PGPException {

        String targetFileName = inputFile.getName().split("\\.")[0] + "_decrypted." + inputFile.getName().split("\\.")[1];
        File decryptedFile = new File(targetFileName);

        byte[] decryptBytes = null;

        URL resPgpPublicKey = getClass().getClassLoader().getResource("vendor_public.txt");
        File filePgpPublicKey = Paths.get(resPgpPublicKey.toURI()).toFile();
        System.out.println("base64secret txt file path : " + filePgpPublicKey.getAbsolutePath());

        URL resExtPgpPrivateKey = getClass().getClassLoader().getResource("client_private.txt");
        File fileExtPgpPrivateKey = Paths.get(resExtPgpPrivateKey.toURI()).toFile();
        System.out.println("base64secret txt file path : " + fileExtPgpPrivateKey.getAbsolutePath());

        String PgpPublicKey = FileUtils.readFileToString(filePgpPublicKey, "UTF-8");
        String pgpExtPrivateKey = FileUtils.readFileToString(fileExtPgpPrivateKey, "UTF-8");
        String paraphase = "passw0rd";

        InputStream keyIn = new ByteArrayInputStream(pgpExtPrivateKey.getBytes(StandardCharsets.UTF_8));
        InputStream pubKey = new ByteArrayInputStream(PgpPublicKey.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        //convert encrypted message to input stream
        InputStream bais = new ByteArrayInputStream(FileUtils.readFileToByteArray(inputFile));

        PgpFileHelper.decryptFile(bais, baos, keyIn,pubKey, paraphase.toCharArray());
        //return the decrypted message
        decryptBytes =  baos.toByteArray();

        try (FileOutputStream fileOutputStream = new FileOutputStream(decryptedFile)){
            fileOutputStream.write(decryptBytes);
            System.out.println("File decrypted success...");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
