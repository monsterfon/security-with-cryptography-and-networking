package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;


import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;

//new
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;


// alice and server
// server generates key pair
// alice generates key pair
// alice sends her public key to server

// use elliptic curve
// use diffie hellman (to so une barve)
// sha256 genereates the symetric key from the shared secret (first 16 bytes)
// new
// server encrypts the concatenated the public keys with its private key  = this is the signature
// server  creates challenge  = random 32 bytes encrypted with the symetric key AES with GCM
// server sends the signature and the challenge to alice

// alice decrypts the signature with the public key of the server
// alice decrypts the challenge with the symetric key and appends the password, hashes, and encrypts
// alice sends

// server decrypts the challenge with the symetric key and compares to its own hash
//  authentification complete
//19.20 gre bus, tri minute prej rabim iti

public class KOLOKVIJ_AgentCommunicationECDH {
    public static void main(String[] args) {

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(256);

                // Generate key pair
                final KeyPair keyPair = kpg.generateKeyPair();


                // send "PK" to server ("PK": A = g^a, "SK": a)
                send("server", keyPair.getPublic().getEncoded());
                print("My contribution to ECDH: PUBLIC KEY %s", hex(keyPair.getPublic().getEncoded()));

                // get PK from server
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("server"));
                final ECPublicKey serverPK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);


                // Run the agreement protocol
                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(serverPK, true);



                //DONE: alice decrypts the signature with the public key of the server
                //we are using SHA-256 with RSA
                 final Signature verifier = Signature.getInstance("RSASSA-PSS");
                verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                // find the recieved public key


                final byte[] serverPKBytes = receive("server"); //we are  always sending bytes
                final X509EncodedKeySpec keySpecs = new X509EncodedKeySpec(serverPKBytes); // key specs are seed for key
                final PublicKey serverPK_rsa = KeyFactory.getInstance("RSA").generatePublic(keySpecs);
                verifier.initVerify(serverPK_rsa);




                // ERROR: no suitable constructor   found for string
                // The correct way to convert an ECPublicKey object to a byte array is to use the getEncoded() method.

                print("I got rsa key: %s", new String(serverPK_rsa.getEncoded(), StandardCharsets.UTF_8));
                // ERROR: method receive in class fri.isp.Agent cannot be applied to given types
                final byte[] signature = receive("server");
                final byte[]  document = receive("server"); //new / moved
                verifier.update(document);
                print("I got: %s", new String(signature, StandardCharsets.UTF_8));
                if (verifier.verify(signature))
                    System.out.println("Valid signature.");
                else
                    System.err.println("Invalid signature.");

                verifier.update(document);



                //DONE: alice decrypts the challenge with the symetric key and appends the password, hashes, and encrypts

                final byte[] challenge_iv = receive("server");
                final byte[] challenge_ct = receive("server");


                // generate a shared AES key
                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: %s", hex(sharedSecret));
                // By default the shared secret will be 32 bytes long,
                // our cipher requires keys of length 16 bytes
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");


                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, challenge_iv)  );
                byte[] message = aes.doFinal(challenge_ct);

                print("Received: " + hex(message));


                aes.init(Cipher.ENCRYPT_MODE, aesKey);
                final byte[] ct = aes.doFinal("PWD".getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aes.getIV();


                send("server", iv);
                send("server", ct);

                print("I'm, done!");
                /*
                */
            }
        });














        env.add(new Agent("server") {
            @Override
            public void task() throws Exception {
                // get PK from alice
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("alice"));
                final ECPublicKey alicePK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);

                final ECParameterSpec dhParamSpec = alicePK.getParams();

                // create your own DH key pair
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(dhParamSpec);
                final KeyPair keyPair = kpg.generateKeyPair();
                send("alice", keyPair.getPublic().getEncoded());
                print("My contribution to ECDH: %s", hex(keyPair.getPublic().getEncoded()));


                //DIGITAL SIGNATURE server needs to encript both the public keys,

                //we are using SHA-256 with RSA
                //HIS keyPair.getPublic().getEncoded()
                // HERS alicePK.getEncoded()
                final String document = "" + keyPair.getPublic().getEncoded() + alicePK.getEncoded();

                final KeyPair key = KeyPairGenerator.getInstance("RSA").generateKeyPair();
                send("alice", key.getPublic().getEncoded());


                final Signature signer = Signature.getInstance("RSASSA-PSS");
                signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                signer.initSign(key.getPrivate());
                signer.update(document.getBytes(StandardCharsets.UTF_8));
                final byte[] signature = signer.sign();

                System.out.println("Signature: " + Agent.hex(signature));
                send("alice", signature);
                send("alice", document.getBytes(StandardCharsets.UTF_8) );

                





                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(alicePK, true);

                //DONE: server  creates challenge  = random 32 bytes encrypted with the symetric key AES with GCM

                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: %s", hex(sharedSecret));
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, aesKey);



                byte[] challenge = new byte[32];
                SecureRandom random = new SecureRandom();
                random.nextBytes(challenge);

                // Encrypt the challenge with the symmetric key
                final byte[] ct = aes.doFinal(challenge);
                final byte[] iv = aes.getIV();



                //DONE: server sends the signature and the challenge to alice

                send("alice", iv);
                send("alice", ct);



                //DONE:  server decrypts the challenge with the symetric key and compares to its own hash
                final byte[] iv_3 = receive("alice");
                final byte[] ct_3 = receive("alice");
                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv_3));
                final byte[] pt = aes.doFinal(ct_3);

                print("I got: %s, this is correct", new String(pt, StandardCharsets.UTF_8));
                print("SERVER: I'm, done!");

                 /* */
                }
        });

        env.connect("alice", "server");
        env.start();
    }
}
