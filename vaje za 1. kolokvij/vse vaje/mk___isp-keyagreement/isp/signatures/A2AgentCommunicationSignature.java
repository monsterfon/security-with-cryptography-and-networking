package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

/*
 * Assuming Alice and Bob know each other's public key, provide integrity and non-repudiation
 * to exchanged messages with ECDSA. Then exchange ten signed messages between Alice and Bob.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();


        // Create key pairs
        final String signingAlgorithm = "SHA256withECDSA";
        final String keyAlgorithm = "EC";

        final KeyPair aliceKP = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                for (int i = 0; i < 10; i++) {

                    // create a message, sign it,
                    final String document = "Bob, is this signed.";
                    final Signature signer = Signature.getInstance(signingAlgorithm);

                    signer.initSign(aliceKP.getPrivate());

                    signer.update(document.getBytes(StandardCharsets.UTF_8));
                    final byte[] signature = signer.sign();

                    byte[] message = document.getBytes();

                    send("bob", message);
                    send("bob", signature);

                    byte[] rec_message = receive("bob");
                    byte[] rec_signature = receive("bob");

                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(bobKP.getPublic());
                    verifier.update(rec_message);

                    if (verifier.verify(rec_signature))
                        System.out.println("message Valid signature." + i);
                    else
                        System.err.println("Invalid signature." + i);

                    ;


                    // and send the message, signature pair to bob
                    // receive the message signarure pair, verify the signature
                    // repeat 10 times
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < 10; i++) {

                    byte[] rec_message = receive("alice");
                    byte[] rec_signature = receive("alice");

                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(aliceKP.getPublic());
                    verifier.update(rec_message);


                    if (verifier.verify(rec_signature))
                        System.out.println("message Valid signature." + i);
                    else
                        System.err.println("Invalid signature." + i);

                    final String document = "Alice, it's signed.";
                    final Signature signer = Signature.getInstance(signingAlgorithm);

                    signer.initSign(bobKP.getPrivate());

                    signer.update(document.getBytes(StandardCharsets.UTF_8));
                    final byte[] signature = signer.sign();

                    byte[] message = document.getBytes();

                    send("alice", message);
                    send("alice", signature);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}