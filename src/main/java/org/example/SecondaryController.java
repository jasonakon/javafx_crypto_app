package org.example;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

import javafx.fxml.FXML;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.openpgp.PGPException;
import org.example.crypto.PgpFileHelper;

public class SecondaryController {

    @FXML
    private void switchToPrimary() throws IOException, PGPException, URISyntaxException {

        //decryptPgpFile();
        pgpDecryptStr();

        App.setRoot("primary");
    }


    public void pgpDecryptStr() throws URISyntaxException, IOException {

        //trim it, just to be safe
        //String message = pgpMapper.getPayload().trim();
        String message_testhardness = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: BCPG v1.66\n" +
                "\n" +
                "hQEMA/EI1rq27SGDAgf/ZRFU7w3LJ8YK51R1Eop6ga7yQ2xgryl4YU+0MxvV/ewS\n" +
                "ma1UPXyMEnSMrXKfv/fJozqj35P+K1TBTY/LYTpMKxW9RMCxUdLdcd3v4XDdEU9f\n" +
                "eXBy5sJTyofY7bkO9h1EcKUFOmbZ6MUdqC9ewA7627WZKu4+RC7Hbh7H1qDvRPdA\n" +
                "/zu3p6r3ogR7QRnF0bKnv6I8P5PHJXjawjOGzyLp9lfqgX4jrK5jsxDJdUw9TrO/\n" +
                "oYqczOoTC8+2MTYG32o1uC27V2Ai3OKSMb7G6noOxGkdru6MbqDUDEr2xHRsrXcP\n" +
                "Cp4YNeKsfSr0/tpLw943t8Iq/wdaiU95GlzL7B3oPcnCg6HClGq0pjfhzUIcFogq\n" +
                "/ko6ITP/kB3y+EV24q4LmcFjwcGAXxKy3ZsZe0TfFpNOEq+OSRfOdX3sfh6G0yMz\n" +
                "bTJ+physypW6gbpG/0g5qYSHL9711GuEW5i4sZBqclMnt8h+DlMpYOLAmQjEepS7\n" +
                "y4ApYCwKpsE43YJgDUbKimvuTsu7AfFQPrKhBQtoGxSHGMlRQ6fSJAcU9hPC7Law\n" +
                "pe27NfECUzlo6ClNAgsGOCDgtkK12gS3Uv+6x4yUo/U4fq2MQhjd0VFz6hXeC/Ke\n" +
                "NXGVshqOjPaEuU8dSPRhWLGGgAXdX1KoolGAwZHbauftwVnK0nsMmNW4k4u4+VFo\n" +
                "1D6kH8Binw6GVtKcAioeZ6kaTxZbcTRSS16n4Sxbl5+et8a5+P3z07K886JUSmu3\n" +
                "ubg60IQ3GGJi/NUn8bv9MExPb5V2mlu3Vq44oRHKAPvZlY3XUiKV3C3AsR34pubm\n" +
                "eoIWpqqVjeODwUlPZ4ZHlKXOylvuH49A95ew/ktCOFtvPhfWGNB14hSRHJg8ZacD\n" +
                "rtB8A5kk09oJZQrdIK0O1QejE1U5xf2JLleUr/me0NrVLE9M1sYpTZdJDA/LzJQx\n" +
                "JyRyZm50NuOD+Dx/a1651DeJUgN39HGYpc2x2tebsSmFFDqXZanUTfWu79igHAay\n" +
                "lTJ/LvWAQWVCA4pTLaNppGdZ/2vkkgcm1IMNHAIEvhC3kTynUrZtQRlEHTOic4ET\n" +
                "91jRIc1K+3qyBr1zJ1TO52pSOAiIo1fJRvkWO0ZkeYu/lR5UN1RyEWcCDU5x6DE9\n" +
                "wJ5DMkO0eJHSilJejiUM7dLHeauK9Dj31adEezDz94Ks5ixQ1ZKLWfUWAK4kYMc4\n" +
                "M0b05pHOn4bfUY5UAk1Of1I7stIxt0OaUraAz6AleGHCR21UMssW689BVWa8ggJf\n" +
                "6hOOBO2bM5Vdb4ZuFwWc9ABE6Aj3AE6810cViqT9CAlGttwzQKtBx+ZsaDOHzAGA\n" +
                "HH36+rQlAOaWXFLL9g5AZzC+YQFnSZSt0YbhOaoXa7o3jFWJi/6TBt+UQEaDIYkA\n" +
                "eKwB0p5Qvf5gCDcbWercVzaTyN7lCbKh5JRWNtlFuPh2o1RXcJlp0PI9ttyBuWq3\n" +
                "z6fU/O7Scn/92J/4CpKOwENm36FTDT2y4jQFXQGgoiipQfVJCtz5shhFY0xxqDHI\n" +
                "YVQovpp64TPMOqlZ/T1Y+txOn728htHod/YsBuW7pN2/xPlePPayVJm4lRpE2kzV\n" +
                "UQ522eaCKNvFL2LRkzCXADq5op/omCWdR7oVa512WZZwKAB7TXZbCO2X7Ox494hJ\n" +
                "ZpXvRdrbWqr7ul1lYdEW0CdOveacwP/CCkWyRi7t44eqVpxV5fzURnhO+rJGE7Mp\n" +
                "DybpjatrxYrCyJPRfGyY/hl4TcWCFjBqLLz5txOQYhe1rIljRBjPu3Iy+OpJmHGw\n" +
                "xhqOn8f1lpSok2CoszTsfkFfhre2ud+iDRPizVLPbRIRSG6jVnz5v+xzhTQ8WzY0\n" +
                "QJwdtqxYsq3gGot4Ikpu3c19SuQnII115YdoIoqVVhImJnQgYWIry+WtiInN5BiO\n" +
                "hp+CcA==\n" +
                "=a/Bd\n" +
                "-----END PGP MESSAGE-----";

        String message = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: BCPG v1.66\n" +
                "\n" +
                "hQEMA/EI1rq27SGDAggAhl0ZeUlZFaFbL0VAzLR6hhhF3l28e5msdhxPsQwYR6MR\n" +
                "6jBnhHcZVwBViD2ZWvVy2o3HDeE/Z/WgLbJtvFYzJpaDsGqb0eNEBNCfKR1ToZDi\n" +
                "3PeJCr0mJM/mlpc4BahxM0ELTEy9skEYl6mkFPuKrM7XTVUQc6s6TGXQB3P8qFA0\n" +
                "6E9jPs4yR2kbrmpsEcLIHg7B7Q1+GAA0Ua5VEFRc84JofWNw191sv+Yq4bVM1Ghg\n" +
                "nCImUgVh+Zt3E4BtONylJ8x8E9NwdeB+iI2zni3cd8m4fZFGJJKhmrIlnKZe14Mq\n" +
                "XVM0taHNNpZPKrWV/RaUx4V0POsp9xaqndkmGAoMzsnCkrOIHdB+IlZWm03NRR6j\n" +
                "SZjkEbWc9sb91n7P8n/3Qg88gbgYn11yGjm2WUb/o4MX49B2ZqIh+dLpRr2lTBKW\n" +
                "bX6oWZPD9GjCXOaZ5iSsC1ISx0ksVpd/6tSDlFEcdR09Ffl+koJrK/MTJxdXTkG2\n" +
                "IRsWvML1vRZmbrz6lqWlk0yoLAzNFxM20m5PGUh+9IXCqnTldg5v5rjYSw69df3l\n" +
                "KXy+jUdCM6Rm8yfo9A2+taRlk9nGmBJ7zhCZHNZY+Su4icT7TLgUwbaqwrPNaRLN\n" +
                "mm2pd9mdfrG6sLcuuDz41C2dhdNu6NsUPKiftmUGhs+cCZyKwgW/f/btqjWb6wA+\n" +
                "YutkIyEQ3j/vLny2RkxiD7oZD687A0R5FdYIlgn+8+MDboxjkKoVmhMkPIu6I++j\n" +
                "alqGf86Wwg8xSl4wxXwhH/+DoXas0TvkTZswHpBLzUQT6F1ANxVd+a6q41GvIxae\n" +
                "aDgPDV9L+tv1Id4eS3NMecBv0lyvYbfkvTrxgNQi0uuqQmDzGpcENKn08gOExiVB\n" +
                "+sUcfNFqGB5AXKyL/SnC7apf8RFQsuo0Wo9DOJAdbHdGPBvsjZOzdcSbATh9xvfx\n" +
                "icBRY7xQzypXqWzrKBhAv5bRO4fVOYF14xhQi+jNG3a8yb0GXGMyOvCPTrSu6yR1\n" +
                "pwXkR9aSwDvaBWDwrWYqUnRp2e6WKO+WuOgZPsmO52tCVxuNsAkYTg6C4WyJNAzb\n" +
                "02Qz6x9jH1tgEj7YhUS+HRgJCH8MU8Rr97cduQK06mqsrBfYLOURL5/oI5CzUfSL\n" +
                "p3Q6F90aV3aSW+DQNA6/VvfEn7FoBNFNGPWNV64IuPRyJbU5nbRKiUGXSf4dcZrY\n" +
                "Zx19soBXrq10owcho2BJjHqw05bhCLM1YtJY5VFyeUm/Et3mZtmQAHsEVSuMpXCs\n" +
                "4Fijt5LjfP7Do9JhBbrXBW+18Bg7b72YvuJkW3twqm0FxR5/z6it8jn1og2iJz5X\n" +
                "j2dETpdsKje8RUSJYZRgV2wOq5yqMX8zen6dKWBef+pq81dxz4jAZypTubDDoq9L\n" +
                "iACGX4zi8MiSAl3zrn5Zm6oq5NwTarE3nmoafvDW4VINq5YLHP/n1FiwZNfnEw0B\n" +
                "Opbe5x24MziHoKGHVY/puWUX2mU97bk5NonRDaXmns836VZdkGl99S/Aw/VR0//Q\n" +
                "y64bNfP5fCtFAKJAOtTnvh3iOr3QHXRrWFz1sjrf6z/ujEztIar+5G7NmYwTbUT8\n" +
                "/ZxLRoInNpL6UxLH8rWgpzzXw0o0dL+G0H0qpWbqciheqv4FczNRLltFD3oQUOqi\n" +
                "4X0X3S8g9FplMdkcF1U8GAwOw7JVEyNXIDA1KKUxGgzGclsovQPMhLf8U9jJncn8\n" +
                "4CUtDJGEQ3FUdELaQvcK6C057Cc/CPxXZmT+cSjGkYQP7nSMl5wB6a2no+LMeDaQ\n" +
                "N+BkYOcmKRPIZndz45UI63IA6BAC1KZUMBPa1DWLKJkdbLdqA7+3FMFh8J39rQI0\n" +
                "W0JM3mwovlUiGpRd+JkTgHdzzUh1yUSYQWu3BnKp0KQnKSMmzvsN+4rnmKJwXJOl\n" +
                "bgBlLD5b+L7ribhB1thttI9/jg==\n" +
                "=IPSd\n" +
                "-----END PGP MESSAGE-----";

        URL resPgpPublicKey = getClass().getClassLoader().getResource("vendor_public.txt");
        File filePgpPublicKey = Paths.get(resPgpPublicKey.toURI()).toFile();
        System.out.println("base64secret txt file path : " + filePgpPublicKey.getAbsolutePath());

        URL resExtPgpPrivateKey = getClass().getClassLoader().getResource("client_private.txt");
        File fileExtPgpPrivateKey = Paths.get(resExtPgpPrivateKey.toURI()).toFile();
        System.out.println("base64secret txt file path : " + fileExtPgpPrivateKey.getAbsolutePath());

        String PgpPublicKey = FileUtils.readFileToString(filePgpPublicKey, "UTF-8");
        String pgpExtPrivateKey = FileUtils.readFileToString(fileExtPgpPrivateKey, "UTF-8");
        String paraphase = "passw0rd";

        String decrypTxt = "";
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        //convert encrypted message to input stream
        ByteArrayInputStream bais = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));
        //get org name from db
        //convert to key
            try(InputStream keyIn = new ByteArrayInputStream(pgpExtPrivateKey.getBytes(StandardCharsets.UTF_8));
                InputStream pubKey = new ByteArrayInputStream(PgpPublicKey.getBytes(StandardCharsets.UTF_8))
            ) {
                PgpFileHelper.decryptFile(bais, baos, keyIn, pubKey, paraphase.toCharArray());
                //return the decrypted message
                decrypTxt = new String(baos.toByteArray());
            } catch (IOException ioe) {
                //dataUpdateAdaptor.updateErrorInternal("Non-Applicable","ER03", "PGP Decryption String Error: " + ioe.toString());
                //LOGGER.error(ioe);
                System.out.println(ioe.getMessage());
            } catch (Exception ex){
                System.out.println(ex.getMessage());
                //LOGGER.error(ex);
            }
            finally {
                //close all the stream
                try {
                    baos.close();
                    bais.close();
                } catch (IOException ignore) {
                    //LOGGER.error(ignore);
                }
            }

        //return the decrypted message
        System.out.println(decrypTxt);
    }

    private void decryptPgpFile() throws URISyntaxException, IOException, PGPException {

        File inputFile = new File("encrypted_new.pdf");
        File decryptedFile = new File("decrypted.pdf");

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