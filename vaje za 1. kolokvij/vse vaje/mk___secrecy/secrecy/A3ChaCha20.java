package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * ChaCha20 stream cipher. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("ChaCha20").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Recall, ChaCha2 requires that you specify the nonce and the counter explicitly.
                 */

                for (int i = 0; i < 10; i++) {
                    byte[] nonce = new byte[12];  // 96-bit nonce
                    SecureRandom random = new SecureRandom();
                    random.nextBytes(nonce);
                    int counter = i;

                    AlgorithmParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce, counter);

                    final Cipher encrypt = Cipher.getInstance("ChaCha20");
                    encrypt.init(Cipher.ENCRYPT_MODE, key, paramSpec);
                    final byte[] pt = message.getBytes();
                    final byte[] cipherText = encrypt.doFinal(pt);

                    send("bob", nonce);
                    send("bob", cipherText);

                    final byte[] response = receive("bob");
                    System.out.println("Alice received: " + new String(response));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < 10; i++) {
                    final byte[] nonce = receive("alice");
                    final byte[] cipherText = receive("alice");

                    int counter = i;
                    AlgorithmParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce, counter);

                    final Cipher decrypt = Cipher.getInstance("ChaCha20");
                    decrypt.init(Cipher.DECRYPT_MODE, key, paramSpec);

                    final byte[] decryptedText = decrypt.doFinal(cipherText);
                    System.out.println("Bob received: " + new String(decryptedText));

                    final String response = "ok";
                    send("alice", response.getBytes());
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
