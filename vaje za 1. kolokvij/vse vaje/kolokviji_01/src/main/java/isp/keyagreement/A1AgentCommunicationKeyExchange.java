package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class A1AgentCommunicationKeyExchange {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {



                // Generate key pair for Alice
                KeyPair aliceKeyPair = generateKeyPair();
                // Send Alice's public key to Bob
                send("bob", aliceKeyPair.getPublic().getEncoded());

                // Receive Bob's public key
                byte[] bobPublicKeyBytes = receive("bob");
                PublicKey bobPublicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(bobPublicKeyBytes));

                // Generate shared secret
                SecretKey sharedSecret = generateSharedSecret(aliceKeyPair.getPrivate(), bobPublicKey);

                // Encrypt and send a message to Bob
                String message = "Hello Bob!";
                byte[] encryptedMessage = encryptMessage(sharedSecret, message);
                send("bob", encryptedMessage);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Generate key pair for Bob
                KeyPair bobKeyPair = generateKeyPair();
                // Send Bob's public key to Alice
                send("alice", bobKeyPair.getPublic().getEncoded());

                // Receive Alice's public key
                byte[] alicePublicKeyBytes = receive("alice");
                PublicKey alicePublicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(alicePublicKeyBytes));

                // Generate shared secret
                SecretKey sharedSecret = generateSharedSecret(bobKeyPair.getPrivate(), alicePublicKey);

                // Receive and decrypt the message from Alice
                byte[] encryptedMessage = receive("alice");
                String decryptedMessage = decryptMessage(sharedSecret, encryptedMessage);
                System.out.println("Bob received: " + decryptedMessage);
            }
        });

        env.connect("alice", "bob");
        env.start();
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        return keyGen.generateKeyPair();
    }

    private static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        return new SecretKeySpec(sharedSecret, 0, 16, "AES");
    }

    private static byte[] encryptMessage(SecretKey key, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12]; // GCM recommended 12 bytes IV
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Arrays.copyOf(iv, iv.length + encryptedMessage.length);
    }

    private static String decryptMessage(SecretKey key, byte[] encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = Arrays.copyOfRange(encryptedMessage, 0, 12);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedMessage = cipher.doFinal(Arrays.copyOfRange(encryptedMessage, 12, encryptedMessage.length));
        return new String(decryptedMessage, StandardCharsets.UTF_8);
    }
}