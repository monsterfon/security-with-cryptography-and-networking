package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using a
 * AES in GCM. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < 10; i++) {


                    final String text = "I hope you get this message intact and in secret. Kisses, Alice." + i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);
                    final byte[] iv = alice.getIV();
                    send("bob", ct);
                    send("bob", iv);
                    final byte[] text_rec = receive("bob");
                    final byte[] iv_rec = receive("bob");
                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, iv_rec);
                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = bob.doFinal(text_rec);
                    System.out.printf("MSG: %s%n", new String(pt2, StandardCharsets.UTF_8));
                }

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < 10; i++) {
                    final byte[] text_rec = receive("alice");
                    final byte[] iv_rec = receive("alice");
                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, iv_rec);
                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = bob.doFinal(text_rec);
                    System.out.printf("MSG: %s%n", new String(pt2, StandardCharsets.UTF_8));
                    final String text = "Thanks, Bob" + i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);
                    final byte[] iv = alice.getIV();
                    send("alice", ct);
                    send("alice", iv);
                }

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
