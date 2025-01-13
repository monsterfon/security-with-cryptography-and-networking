package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class A2AgentCommunicationSignature {
    public static void main(String[] args) {
        try {
            final Environment env = new Environment();
            final KeyPair aliceKeyPair = generateKeyPair();
            final KeyPair bobKeyPair = generateKeyPair();

            env.add(new Agent("alice") {
                @Override
                public void task() throws Exception {
                    for (int i = 0; i < 10; i++) {
                        // Create a message
                        final String message = "Message " + (i + 1) + " from Alice";

                        // Sign the message
                        final byte[] signature = signMessage(message, aliceKeyPair);

                        // Send the message and signature to Bob
                        send("bob", message.getBytes(StandardCharsets.UTF_8));
                        send("bob", signature);

                        // Receive the message and signature from Bob
                        final byte[] receivedMessage = receive("bob");
                        final byte[] receivedSignature = receive("bob");

                        // Verify the signature
                        if (verifyMessage(receivedMessage, receivedSignature, bobKeyPair)) {
                            System.out.println("Alice: Valid signature from Bob");
                        } else {
                            System.err.println("Alice: Invalid signature from Bob");
                        }
                    }
                }
            });

            env.add(new Agent("bob") {
                @Override
                public void task() throws Exception {
                    for (int i = 0; i < 10; i++) {
                        // Receive the message and signature from Alice
                        final byte[] receivedMessage = receive("alice");
                        final byte[] receivedSignature = receive("alice");

                        // Verify the signature
                        if (verifyMessage(receivedMessage, receivedSignature, aliceKeyPair)) {
                            System.out.println("Bob: Valid signature from Alice");
                        } else {
                            System.err.println("Bob: Invalid signature from Alice");
                        }

                        // Create a message
                        final String message = "Message " + (i + 1) + " from Bob";

                        // Sign the message
                        final byte[] signature = signMessage(message, bobKeyPair);

                        // Send the message and signature to Alice
                        send("alice", message.getBytes(StandardCharsets.UTF_8));
                        send("alice", signature);
                    }
                }
            });

            env.connect("alice", "bob");
            env.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeyPair() throws Exception {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        return keyGen.generateKeyPair();
    }

    private static byte[] signMessage(String message, KeyPair keyPair) throws Exception {
        final Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(message.getBytes(StandardCharsets.UTF_8));
        return signer.sign();
    }

    private static boolean verifyMessage(byte[] message, byte[] signature, KeyPair keyPair) throws Exception {
        final Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        return verifier.verify(signature);
    }
}