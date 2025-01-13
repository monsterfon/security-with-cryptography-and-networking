package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using a
 * AES in counter mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AESInCTRMode {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("AES").generateKey();

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
                 * Do not forget: In CBC (and CTR mode), you have to also
                 * send the IV. The IV can be accessed via the
                 * cipher.getIV() call
                 */

                for (int i = 0; i < 10; i++) {
                    final Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding");
                    IvParameterSpec iv = new IvParameterSpec(new byte[16]);

                    final byte[] pt = message.getBytes();

                    encrypt.init(Cipher.ENCRYPT_MODE, key, iv);
                    final byte[] cipherText = encrypt.doFinal(pt);

                    send("bob", iv.getIV());
                    send("bob", cipherText);

                    IvParameterSpec ivSpec = new IvParameterSpec(receive("bob"));
                    Cipher aesCipher = Cipher.getInstance("AES/CTR/NoPadding");
                    aesCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

                    byte[] plaintext = aesCipher.doFinal(receive("bob"));

                    System.out.println("Alice received: " + new String(plaintext));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /* TODO STEP 4
                 * Bob receives, decrypts and displays a message.
                 * Once you obtain the byte[] representation of cipher parameters,
                 * you can load them with:
                 *
                 *   IvParameterSpec ivSpec = new IvParameterSpec(iv);
                 *   aes.init(Cipher.DECRYPT_MODE, my_key, ivSpec);
                 *
                 * You then pass this object to the cipher init() method call.*
                 */
                final String bob_message = "ok";
                for (int i = 0; i < 10; i++) {

                    byte[] iv = receive("alice");
                    byte[] cipherText = receive("alice");

                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    Cipher aesCipher = Cipher.getInstance("AES/CTR/NoPadding");
                    aesCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

                    byte[] plaintext = aesCipher.doFinal(cipherText);

                    System.out.println("Bob received: " + new String(plaintext));

                    final Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding");

                    IvParameterSpec iv2 = new IvParameterSpec(new byte[16]);

                    final byte[] pt = bob_message.getBytes();

                    encrypt.init(Cipher.ENCRYPT_MODE, key, iv2);
                    final byte[] cipherText2 = encrypt.doFinal(pt);

                    send("alice", iv2.getIV());
                    send("alice", cipherText2);

                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
