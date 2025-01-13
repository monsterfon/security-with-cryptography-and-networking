package isp.secrecy;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class A4ExhaustiveSearch {
    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        byte[] keyBytes = new byte[8];
        keyBytes[5] = (byte) 3;
        keyBytes[6] = (byte) 100;
        keyBytes[7] = (byte) 255;

        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "DES");

        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        byte[] encryptedMessage = cipher.doFinal(message.getBytes());

        byte[] key = bruteForceKey(encryptedMessage, message);
        if (key != null) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < key.length; i++) {
                sb.append(String.format("%02X", key[i]));
                if (i < key.length - 1) {
                    sb.append(" ");
                }
            }

            System.out.println("Key found: " + sb.toString());
        } else {
            System.out.println("Key not found.");
        }
    }

    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        for (int b1 = 0; b1 < 256; b1++) {
            for (int b2 = 0; b2 < 256; b2++) {
                for (int b3 = 0; b3 < 256; b3++) {
                    byte[] key = new byte[8];
                    key[5] = (byte) b1;
                    key[6] = (byte) b2;
                    key[7] = (byte) b3;

                    SecretKeySpec keySpec = new SecretKeySpec(key, "DES");

                    Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

                    cipher.init(Cipher.DECRYPT_MODE, keySpec);
                    try {
                        byte[] decryptedText = cipher.doFinal(ct);
                        String decryptedMessage = new String(decryptedText);

                        if (decryptedMessage.equals(message)) {
                            return key;
                        }
                    } catch (Exception e) {
                    }
                }
            }
        }
        return null;
    }
}
