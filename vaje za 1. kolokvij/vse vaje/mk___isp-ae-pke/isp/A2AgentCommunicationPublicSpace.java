package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * TASK:
 * We want to send a large chunk of data from Alice to Bob while maintaining its integrity and considering
 * the limitations of communication channels -- we have three such channels:
 * - Alice to Bob: an insecure channel, but has high bandwidth and can thus transfer large files
 * - Alice to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * - Bob to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * <p>
 * The plan is to make use of the public-space technique:
 * - Alice creates the data and computes its digest
 * - Alice sends the data to Bob, and sends the encrypted digest to Public Space
 * - Channel between Alice and Public space is secured with ChaCha20-Poly1305 (Alice and Public space share
 * a ChaCha20 key)
 * - Public space forwards the digest to Bob
 * - The channel between Public Space and Bob is secured but with AES in GCM mode (Bob and Public space share
 * an AES key)
 * - Bob receives the data from Alice and the digest from Public space
 * - Bob computes the digest over the received data and compares it to the received digest
 * <p>
 * Further instructions are given below.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AgentCommunicationPublicSpace {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        final Key Alice_key = KeyGenerator.getInstance("ChaCha20").generateKey();
        final Key Bob_key = KeyGenerator.getInstance("AES").generateKey();


        // Create a ChaCha20 key that is used by Alice and the public-space
        // Create an AES key that is used by Bob and the public-space

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // a payload of 200 MB
                final byte[] data = new byte[200 * 1024 * 1024];
                new SecureRandom().nextBytes(data);

                send("bob", data);

                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(data);

                byte[] nonce = new byte[12]; // ChaCha20 uses a 12-byte nonce
                new SecureRandom().nextBytes(nonce);

                Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
                cipher.init(Cipher.ENCRYPT_MODE, Alice_key, new IvParameterSpec(nonce));

                byte[] encryptedHash = cipher.doFinal(hash);

                send("public-space", encryptedHash);
                send("public-space", nonce);

                // Alice sends the data directly to Bob
                // The channel between Alice and Bob is not secured
                // Alice then computes the digest of the data and sends the digest to public-space
                // The channel between Alice and the public-space is secured with ChaCha20-Poly1305
                // Use the key that you have created above.

            }
        });

        env.add(new Agent("public-space") {
            @Override
            public void task() throws Exception {
                final byte[] digest = receive("alice");
                final byte[] nonce = receive("alice");

                final Cipher decrypt = Cipher.getInstance("ChaCha20-Poly1305");

                decrypt.init(Cipher.DECRYPT_MODE, Alice_key, new IvParameterSpec(nonce));

                final byte[] decryptedText = decrypt.doFinal(digest);

                final Cipher public_space = Cipher.getInstance("AES/GCM/NoPadding");
                public_space.init(Cipher.ENCRYPT_MODE, Bob_key);
                final byte[] ct = public_space.doFinal(decryptedText);
                final byte[] iv = public_space.getIV();

                send("bob", ct);
                send("bob", iv);

                // Receive the encrypted digest from Alice and decrypt ChaCha20 and
                // the key that you share with Alice
                // Encrypt the digest with AES-GCM and the key that you share with Bob and
                // send the encrypted digest to Bob

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive the data from Alice and compute the digest over it using SHA-256
                final byte[] data_a = receive("alice");
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(data_a);

                // Receive the encrypted digest from the public-space, decrypt it using AES-GCM
                // and the key that Bob shares with the public-space

                final byte[] ct_p = receive("public-space");
                final byte[] iv_p = receive("public-space");

                final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");

                final GCMParameterSpec specs = new GCMParameterSpec(128, iv_p);
                bob.init(Cipher.DECRYPT_MODE, Bob_key, specs);
                final byte[] digest_bob = bob.doFinal(ct_p);

                // Compare the computed digest and the received digest and print the string
                // "data valid" if the verification succeeds, otherwise print "data invalid"

                if (Arrays.equals(hash, digest_bob)) {
                    System.out.println("data valid");
                } else {
                    System.out.println("data invalid");
                }

            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "public-space");
        env.connect("public-space", "bob");
        env.start();
    }
}
