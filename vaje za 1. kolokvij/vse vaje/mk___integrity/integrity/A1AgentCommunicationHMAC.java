package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, provide integrity to the channel
 * using HMAC implemted with SHA256. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        final Mac alice = Mac.getInstance("HmacSHA256");
        final Mac bob = Mac.getInstance("HmacSHA256");

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i <10 ; i++) {
                    final String text = "I hope you get this message intact. Kisses, Alice.";
                    alice.init(key);
                    final byte[] pt = alice.doFinal(text.getBytes(StandardCharsets.UTF_8));

                    final String messageHmacAsString = Agent.hex(pt);
                    System.out.println("HMAC: " + messageHmacAsString);

                    send("bob", text.getBytes(StandardCharsets.UTF_8));
                    send("bob", pt);

                    final byte[] responseTextBytes = receive("bob");
                    final byte[] responseHmacBytes = receive("bob");

                    final String responseText = new String(responseTextBytes, StandardCharsets.UTF_8);

                    final byte[] computedResponseHmac = alice.doFinal(responseTextBytes);

                    if (MessageDigest.isEqual(responseHmacBytes, computedResponseHmac)) {
                        System.out.println("Alice: Integrity verified for Bob's response - " + responseText);
                    } else {
                        System.out.println("Alice: Integrity check failed for Bob's response!");
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < 10; i++) {

                    final byte[] receivedTextBytes = receive("alice");
                    final byte[] receivedHmacBytes = receive("alice");

                    final String receivedText = new String(receivedTextBytes, StandardCharsets.UTF_8);

                    bob.init(key);
                    final byte[] computedHmac = bob.doFinal(receivedTextBytes);

                    if (MessageDigest.isEqual(receivedHmacBytes, computedHmac)) {
                        System.out.println("Bob: Integrity verified for Alice's message - " + receivedText);

                        final String responseText = "ok, Alice!";
                        bob.init(key);
                        final byte[] responseHmac = bob.doFinal(responseText.getBytes(StandardCharsets.UTF_8));

                        send("alice", responseText.getBytes(StandardCharsets.UTF_8));
                        send("alice", responseHmac);
                    } else {
                        System.out.println("Bob: Integrity check failed for Alice's message!");
                    }
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
