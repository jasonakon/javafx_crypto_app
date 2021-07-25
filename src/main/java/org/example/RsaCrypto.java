package org.example;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.paint.Color;
import javafx.stage.Stage;
import org.apache.commons.io.FileUtils;
import org.example.crypto.RsaUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RsaCrypto {

    private Stage stage;
    private String rsaKeySize;

    @FXML
    public TextField textfieldRsaEncrypt;
    public TextField textfieldRsaEncryptOutput;
    public TextField textfieldRsaDecrypt;
    public TextField textfieldRsaDecryptOutput;
    public Button butRsaEncrypt;
    public Label LabelRsaEncrypt;
    public Label LabelRsaDecrypt;
    public Label LabelRsaGenerateKeys;
    public ToggleGroup toggleRsaKeySizeGroup;

    public TextField textfieldRsaEncryptedText;
    public TextField textfieldRsaSignature;
    public Label LabelRsaVerifySignature;
    public Label LabelRsaGenerateKeySize;
    public MenuButton butMenuRsaGenerateKeys;

    public void setStage(Stage stage){
        this.stage = stage;
    }

    @FXML
    private void encryptRsa() throws URISyntaxException, IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        if(textfieldRsaEncrypt.getText().isEmpty()){
            LabelRsaEncrypt.setTextFill(Color.color(1,0,0));
            LabelRsaEncrypt.setText("Please insert your text !");
        } else {
            try {
                URL resExtRsaPublicKey = getClass().getClassLoader().getResource("rsa_public_client.txt");
                File fileExtRsaPublicKey = Paths.get(resExtRsaPublicKey.toURI()).toFile();
                System.out.println("rsa public client file path : " + fileExtRsaPublicKey.getAbsolutePath());

                String extRsaPublicKey = FileUtils.readFileToString(fileExtRsaPublicKey, "UTF-8");
                PublicKey pub = RsaUtil.getRsaPublic(extRsaPublicKey);

                textfieldRsaEncryptOutput.setText(RsaUtil.encrypt(textfieldRsaEncrypt.getText(), pub));

                LabelRsaEncrypt.setTextFill(Color.color(0,0,1));
                LabelRsaEncrypt.setText("RSA encrypt successfully.");
            } catch (Exception e){
                System.out.println("Error in RSA Encryption : " + e.getMessage());
            }
        }
    }

    @FXML
    private void decryptRsa(){
        if(textfieldRsaDecrypt.getText().isEmpty()){
            LabelRsaDecrypt.setTextFill(Color.color(1,0,0));
            LabelRsaDecrypt.setText("Please insert your RSA CipherText !");
        } else {
            try {
                URL resExtRsaPrivateKey = getClass().getClassLoader().getResource("rsa_private_client.txt");
                File fileExtRsaPrivateKey = Paths.get(resExtRsaPrivateKey.toURI()).toFile();
                System.out.println("rsa private client file path : " + fileExtRsaPrivateKey.getAbsolutePath());

                String extRsaPrivateKey = FileUtils.readFileToString(fileExtRsaPrivateKey, "UTF-8");
                PrivateKey priv = RsaUtil.getRsaPrivate(extRsaPrivateKey);

                textfieldRsaDecryptOutput.setText(RsaUtil.decrypt(textfieldRsaDecrypt.getText(), priv));

                LabelRsaDecrypt.setTextFill(Color.color(0, 0, 1));
                LabelRsaDecrypt.setText("RSA decrypt successfully.");
            } catch (Exception e) {
                System.out.println("Error in RSA Decryption : " + e.getMessage());
            }
        }
    }

    @FXML
    private void generateRsaKeys(){
        RadioButton toggleBut = (RadioButton) toggleRsaKeySizeGroup.getSelectedToggle();
        int rsaKeySize = Integer.parseInt(toggleBut.getText());
        RsaUtil.generateRsaKeys(rsaKeySize);
        LabelRsaGenerateKeys.setTextFill(Color.color(0,0,1));
        LabelRsaGenerateKeys.setText("RSA key pair generated successfully | size : " + rsaKeySize);
    }

    @FXML
    private void verifyRsaSignature() throws Exception {
        String rsaEncryptedText = textfieldRsaEncryptedText.getText();
        String rsaSignature = textfieldRsaSignature.getText();

        URL resExtRsaPublicKey = getClass().getClassLoader().getResource("vendor_public_test.txt");
        File fileExtRsaPublicKey = Paths.get(resExtRsaPublicKey.toURI()).toFile();
        System.out.println("rsa public client file path : " + fileExtRsaPublicKey.getAbsolutePath());

        String extRsaPublicKey = FileUtils.readFileToString(fileExtRsaPublicKey, "UTF-8");
        PublicKey pub = RsaUtil.getRsaPublic(extRsaPublicKey);

        Boolean isVerified = RsaUtil.verify(rsaEncryptedText, rsaSignature, pub);
        LabelRsaVerifySignature.setText("RSA Signature Verification Result : " + isVerified);

        System.out.println("verification : " + isVerified);
    }

    @FXML
    private void rsaBack() throws IOException {
        System.out.println("Going back to main");
        App.setRoot("main");
    }


}
