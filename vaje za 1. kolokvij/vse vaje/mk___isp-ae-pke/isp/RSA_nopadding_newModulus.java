import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.Cipher;

public class RSAExample {
    public static void main(String[] args) throws Exception {
        // Define RSA cipher specifications
        String algorithm = "RSA/ECB/NoPadding";
        
        // Example message
        String message = "I would like to keep this text confidential, Bob. Kind regards, Alice.";
        byte[] pt = message.getBytes(StandardCharsets.UTF_8);
        System.out.println("Message: " + message);
        System.out.println("PT: " + Agent.hex(pt));

        // Generate RSA key pair with a different modulus size
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024); // Example modulus size
        KeyPair bobKP = kpg.generateKeyPair();

        // Encrypt the plaintext
        Cipher rsaEnc = Cipher.getInstance(algorithm);
        rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
        byte[] ct = rsaEnc.doFinal(pt);
        System.out.println("CT: " + Agent.hex(ct));

        // Decrypt the ciphertext
        Cipher rsaDec = Cipher.getInstance(algorithm);
        rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
        byte[] decryptedText = rsaDec.doFinal(ct);
        System.out.println("PT: " + Agent.hex(decryptedText));
        String message2 = new String(decryptedText, StandardCharsets.UTF_8);
        System.out.println("Message: " + message2);
    }
}