package org.example;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.paint.Color;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.example.crypto.AESCryptography;

import java.io.File;
import java.io.IOException;

public class AesFileCrypto {
    private Stage stage;
    private File selectedEncryptRawFile;
    private File selectedDecryptRawFile;

    @FXML
    public Button butSelectAesFile;
    public Button butAesFileEncrypt;
    public Label LabelAesFileEncrypt;

    public Button butSelectAesFileEncrypted;
    public Button butAesFileDecrypt;
    public Label LabelAesFileDecrypt;

    public TextField textFieldAESPasswordInput;

    public void setStage(Stage stage){
        this.stage = stage;
    }

    @FXML
    private void selectEncryptAesFile(){
        // Get File:
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open raw file");
        selectedEncryptRawFile =  fileChooser.showOpenDialog(stage);

        // Update Label Notification:
        LabelAesFileEncrypt.setTextFill(Color.color(0,0,1));
        LabelAesFileEncrypt.setText("File selected : " + selectedEncryptRawFile.getName());
    }

    @FXML
    private void encryptAesFile(){
        if(textFieldAESPasswordInput.getText().isEmpty()){
            LabelAesFileEncrypt.setTextFill(Color.color(1,0,0));
            LabelAesFileEncrypt.setText("Please enter your password !");
            return;
        }

        if(selectedEncryptRawFile == null){
            LabelAesFileEncrypt.setTextFill(Color.color(1,0,0));
            LabelAesFileEncrypt.setText("Please select your file !");
        } else {
            try {
                String targetFileName = selectedEncryptRawFile.getName().split("\\.")[0] + "_aes_encrypted." + selectedEncryptRawFile.getName().split("\\.")[1];
                File encryptedAesFile = new File(targetFileName);

                AESCryptography.encrypt(selectedEncryptRawFile, textFieldAESPasswordInput.getText(), encryptedAesFile);
                LabelAesFileEncrypt.setTextFill(Color.color(0, 1, 0));
                LabelAesFileEncrypt.setText("File : " + selectedEncryptRawFile.getName() + " is successfully encrypted !");
            } catch (Exception e){
                LabelAesFileEncrypt.setTextFill(Color.color(1, 0, 0));
                LabelAesFileEncrypt.setText("File Encryption Failed : " + "File : " + selectedEncryptRawFile.getName() + " Error : " + e.getMessage());
            }
        }
    }

    @FXML
    private void selectDecryptAesFile(){
        // Get File:
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open raw file");
        selectedDecryptRawFile =  fileChooser.showOpenDialog(stage);

        // Update Label Notification:
        LabelAesFileDecrypt.setTextFill(Color.color(0,0,1));
        LabelAesFileDecrypt.setText("File selected : " + selectedDecryptRawFile.getName());
    }

    @FXML
    private void decryptAesFile(){
        if(textFieldAESPasswordInput.getText().isEmpty()){
            LabelAesFileDecrypt.setTextFill(Color.color(1,0,0));
            LabelAesFileDecrypt.setText("Please enter your password !");
            return;
        }

        if(selectedDecryptRawFile == null){
            LabelAesFileDecrypt.setTextFill(Color.color(1,0,0));
            LabelAesFileDecrypt.setText("Please select your file !");
        } else {
            try {
                String targetFileName = selectedDecryptRawFile.getName().split("\\.")[0] + "_aes_decrypted." + selectedDecryptRawFile.getName().split("\\.")[1];
                File decryptedAesFile = new File(targetFileName);

                AESCryptography.decrypt(selectedDecryptRawFile, textFieldAESPasswordInput.getText(), decryptedAesFile);
                LabelAesFileDecrypt.setTextFill(Color.color(0, 1, 0));
                LabelAesFileDecrypt.setText("File : " + selectedDecryptRawFile.getName() + " is successfully decrypted !");
            } catch (Exception e){
                LabelAesFileDecrypt.setTextFill(Color.color(1, 0, 0));
                LabelAesFileDecrypt.setText("File Decryption Failed : " + "File : " + selectedDecryptRawFile.getName() + " Error : " + e.getMessage());
            }
        }
    }

    @FXML
    private void aesBack() throws IOException {
        System.out.println("Going back to main");
        App.setRoot("main");
    }

}
