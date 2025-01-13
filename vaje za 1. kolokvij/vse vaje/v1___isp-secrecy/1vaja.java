import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.util.Scanner;

public class SymmetricCipherExample {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Choose an algorithm (RC4, ChaCha20, AES): ");
        String algorithm = scanner.nextLine().trim();

        final String message = "Hi Bob, this is Alice.";
        System.out.println("[MESSAGE]: " + message);

        Key key = null;
        Cipher encrypt = null;
        Cipher decrypt = null;

        switch (algorithm) {
            case "RC4":
                key = KeyGenerator.getInstance("RC4").generateKey();
                encrypt = Cipher.getInstance("RC4");
                decrypt = Cipher.getInstance("RC4");
                break;
            case "ChaCha20":
                key = KeyGenerator.getInstance("ChaCha20").generateKey();
                encrypt = Cipher.getInstance("ChaCha20");
                decrypt = Cipher.getInstance("ChaCha20");
                break;
            case "AES":
                key = KeyGenerator.getInstance("AES").generateKey();
                encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
                decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
                break;
            default:
                System.out.println("Unsupported algorithm.");
                return;
        }

        final byte[] pt = message.getBytes();
        System.out.println("[PT]: " + bytesToHex(pt));

        // Encrypt
        byte[] cipherText;
        byte[] iv = null;

        if (algorithm.equals("ChaCha20")) {
            final byte[] nonce = new byte[12]; // Nonce for ChaCha20
            encrypt.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
            cipherText = encrypt.doFinal(pt);
            System.out.println("[CT]: " + bytesToHex(cipherText));
        } else if (algorithm.equals("AES")) {
            encrypt.init(Cipher.ENCRYPT_MODE, key);
            cipherText = encrypt.doFinal(pt);
            iv = encrypt.getIV(); // Get the IV used for AES
            System.out.println("[CT]: " + bytesToHex(cipherText));
        } else {
            encrypt.init(Cipher.ENCRYPT_MODE, key);
            cipherText = encrypt.doFinal(pt);
            System.out.println("[CT]: " + bytesToHex(cipherText));
        }

        // Decrypt
        byte[] dt;
        if (algorithm.equals("AES")) {
            decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            dt = decrypt.doFinal(cipherText);
        } else if (algorithm.equals("ChaCha20")) {
            decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[12])); // Use the same nonce
            dt = decrypt.doFinal(cipherText);
        } else {
            decrypt.init(Cipher.DECRYPT_MODE, key);
            dt = decrypt.doFinal(cipherText);
        }

        System.out.println("[PT]: " + bytesToHex(dt));
        System.out.println("[MESSAGE]: " + new String(dt));
    }

    // Helper method to convert bytes to hexadecimal format
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
