package org.example;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.*;

/**
 * JavaFX App
 */
public class App extends Application {

    private static Scene scene;

    @Override
    public void start(Stage stage) throws IOException {

        FXMLLoader fxmlPgpFileCryptoLoader = loadFXML("main");
        Parent root = (Parent) fxmlPgpFileCryptoLoader.load();
        ((MainController) fxmlPgpFileCryptoLoader.getController()).setStage(stage);


        int[] arrival = {1,3,5};
        int[] duration = {2,2,2};

        int counter = 0;

        for(int i = 1; i < arrival.length; i++){
            if((arrival[i-1] + duration[i-1]) < arrival[i]){
                counter += 1;
            } else {
                
            }
        }






//        FXMLLoader fxmlPgpRsaCryptoLoader = loadFXML("rsa_crypto");
//        root = (Parent) fxmlPgpFileCryptoLoader.load();
//        ((RsaCrypto) fxmlPgpRsaCryptoLoader.getController()).setStage(stage);

        scene = new Scene(loadFXML("main").load(), 640, 700);
        stage.setScene(scene);
        stage.show();
    }

    static void setRoot(String fxml) throws IOException {
        scene.setRoot(loadFXML(fxml).load());
    }

    private static FXMLLoader loadFXML(String fxml) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(App.class.getResource(fxml + ".fxml"));
        return fxmlLoader;
    }

    public static void main(String[] args) {
        launch();
    }

}