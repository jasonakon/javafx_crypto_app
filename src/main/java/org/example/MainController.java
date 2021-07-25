package org.example;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.stage.Stage;

import java.io.IOException;

public class MainController {

    private Stage stage;

    public void setStage(Stage stage){
        this.stage = stage;
    }

    @FXML
    private void switchToPgpFileCrypto() throws IOException {
        App.setRoot("pgp_file_crypto");
        System.out.println("Switched to PGP File Crypto");
    }

    @FXML
    private void switchToRsaCrypto() throws IOException {
        App.setRoot("rsa_crypto");
        System.out.println("Switched to RSA Crypto");
    }

    @FXML
    private void switchToPgpStrCrypto() throws IOException {
        App.setRoot("pgp_str_crypto");
        System.out.println("Switched to PGP Str Crypto");
    }

    @FXML
    private void switchToAesCrypto() throws IOException {
        App.setRoot("aes_file_crypto");
        System.out.println("Switched to AES Crypto");
    }



    private static FXMLLoader loadFXML(String fxml) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(App.class.getResource(fxml + ".fxml"));
        return fxmlLoader;
    }
}
