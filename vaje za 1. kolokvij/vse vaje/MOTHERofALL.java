//kolokvij cheat sheet



package isp.kolokvij;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.io.InputStream;
import java.security.interfaces.ECPublicKey;


/**
 * Comprehensive cheat sheet for Information Security & Privacy Kolokvij I
 * Contains all cryptographic operations from course material including:
 * - Key Generation (Symmetric/Asymmetric)
 * - Encryption/Decryption (AES, RSA, ChaCha20)
 * - Message Authentication (HMAC)
 * - Digital Signatures (RSA, RSA-PSS)
 * - Key Exchange (DH, ECDH)
 * - Hybrid Encryption
 * - Hashing and Key Derivation
 */
public class KolokvijICheatSheet {
    // Common constants
    private static final int AES_KEY_SIZE = 256;
    private static final int RSA_KEY_SIZE = 2048;
    private static final int EC_KEY_SIZE = 256;
    private static final int DH_KEY_SIZE = 2048;

    // Algorithm strings
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final String AES_CBC = "AES/CBC/PKCS5Padding";
    private static final String AES_CTR = "AES/CTR/NoPadding";
    private static final String RSA_OAEP = "RSA/ECB/OAEPPadding";
    private static final String CHACHA20 = "ChaCha20";

    // Hybrid encryption result container
    public static class HybridCipherResult {
        public byte[] encryptedKey;
        public byte[] iv;
        public byte[] ciphertext;
    }

    /**
     * Generates symmetric encryption key for AES
     * Keywords: symmetric encryption, session key, key generation
     * Used for: Data encryption with AES in various modes (GCM, CBC, CTR)
     */
    public static Key generateAESKey() throws NoSuchAlgorithmException {
        return KeyGenerator.getInstance("AES").generateKey();
    }

    /**
     * Generates RSA key pair for asymmetric cryptography
     * Keywords: asymmetric encryption, public key, private key, RSA
     * Used for: Public key encryption, digital signatures, key exchange
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(RSA_KEY_SIZE);
        return kpg.generateKeyPair();
    }

    /**
     * Generates key for HMAC operations
     * Keywords: message authentication code, integrity, HMAC
     * Used for: Message authentication and integrity verification
     */
    public static Key generateHMACKey() throws NoSuchAlgorithmException {
        return KeyGenerator.getInstance("HmacSHA256").generateKey();
    }

    /**
     * Generates Diffie-Hellman key pair for key exchange
     * Keywords: key exchange, DH, public key cryptography
     * Used for: Establishing shared secrets between parties
     */
    public static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(DH_KEY_SIZE);
        return kpg.generateKeyPair();
    }

    /**
     * Encrypts data using AES in GCM mode (authenticated encryption)
     * Keywords: authenticated encryption, GCM mode, confidentiality, integrity
     * Used for: Secure data encryption with built-in authentication
     */
    public static byte[] encryptAESGCM(Key key, byte[] plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_GCM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plainText);
    }

    /**
     * Decrypts AES-GCM encrypted data and verifies integrity
     * Keywords: authenticated decryption, GCM mode, integrity check
     * Used for: Secure decryption with authentication verification
     */
    public static byte[] decryptAESGCM(Key key, byte[] cipherText, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec specs = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, specs);
        return cipher.doFinal(cipherText);
    }

    /**
     * Encrypts data using AES in CBC mode with PKCS5 padding
     * Keywords: CBC mode, initialization vector (IV), block cipher
     * Used for: Block cipher encryption when authentication not needed
     */
    public static byte[] encryptAESCBC(Key key, byte[] plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CBC);
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return cipher.doFinal(plainText);
    }

    /**
     * Encrypts data using AES in CTR mode with counter
     * Keywords: CTR mode, counter, stream cipher, nonce
     * Used for: Stream cipher encryption, parallelizable encryption
     */
    public static byte[] encryptAESCTR(Key key, byte[] plainText, int counter) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CTR);
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        byte[] ivWithCounter = new byte[16];
        System.arraycopy(nonce, 0, ivWithCounter, 0, 12);
        ivWithCounter[12] = (byte)(counter >>> 24);
        ivWithCounter[13] = (byte)(counter >>> 16);
        ivWithCounter[14] = (byte)(counter >>> 8);
        ivWithCounter[15] = (byte)counter;
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivWithCounter));
        return cipher.doFinal(plainText);
    }

    /**
     * Encrypts data using ChaCha20 stream cipher
     * Keywords: stream cipher, ChaCha20, nonce, counter
     * Used for: Alternative to AES, good for software implementations
     */
    public static byte[] encryptChaCha20(Key key, byte[] plainText, int counter) throws Exception {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance(CHACHA20);
        cipher.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, counter));
        return cipher.doFinal(plainText);
    }

    /**
     * Encrypts data using RSA with OAEP padding
     * Keywords: asymmetric encryption, RSA, OAEP padding, public key
     * Used for: Encrypting small data amounts with public key
     */
    public static byte[] encryptRSA(PublicKey key, byte[] plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_OAEP);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plainText);
    }

    /**
     * Creates RSA digital signature with SHA-256
     * Keywords: digital signature, RSA, SHA-256, private key
     * Used for: Creating digital signatures for data authentication
     */
    public static byte[] signRSA(PrivateKey key, byte[] message) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(message);
        return signer.sign();
    }

    /**
     * Creates RSA-PSS signature (probabilistic variant)
     * Keywords: PSS, digital signature, RSA, salt
     * Used for: Modern RSA signing with better security properties
     */
    public static byte[] signRSAPSS(PrivateKey key, byte[] message) throws Exception {
        Signature signer = Signature.getInstance("RSASSA-PSS");
        PSSParameterSpec pssParams = new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        signer.setParameter(pssParams);
        signer.initSign(key);
        signer.update(message);
        return signer.sign();
    }

    /**
     * Verifies RSA-PSS signature
     * Keywords: signature verification, PSS, public key
     * Used for: Verifying RSA-PSS signatures with proper parameters
     */
    public static boolean verifyRSAPSS(PublicKey key, byte[] message, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance("RSASSA-PSS");
        PSSParameterSpec pssParams = new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        verifier.setParameter(pssParams);
        verifier.initVerify(key);
        verifier.update(message);
        return verifier.verify(signature);
    }

    /**
     * Creates HMAC for message authentication
     * Keywords: message authentication code, HMAC, integrity
     * Used for: Ensuring message integrity and authenticity
     */
    public static byte[] createHMAC(Key key, byte[] message) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(key);
        return hmac.doFinal(message);
    }

    /**
     * Verifies HMAC tags securely (constant time)
     * Keywords: timing attacks, constant-time comparison, HMAC verification
     * Used for: Securely comparing HMACs without timing leaks
     */
    public static boolean verifyHMAC(byte[] tag1, byte[] tag2) {
        return MessageDigest.isEqual(tag1, tag2);
    }

    /**
     * Performs Diffie-Hellman key agreement
     * Keywords: key agreement, shared secret, DH protocol
     * Used for: Establishing shared secret between two parties
     */
    public static byte[] performDH(PrivateKey myPrivateKey, PublicKey theirPublicKey) throws Exception {
        KeyAgreement dh = KeyAgreement.getInstance("DH");
        dh.init(myPrivateKey);
        dh.doPhase(theirPublicKey, true);
        return dh.generateSecret();
    }

    /**
     * Generates EC key pair for elliptic curve operations
     * Keywords: ECDH, elliptic curve, key generation
     * Used for: More efficient alternative to RSA/DH key pairs
     */
    public static KeyPair generateECKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(EC_KEY_SIZE);
        return kpg.generateKeyPair();
    }

    /**
     * Sets up ECDH from received public key bytes
     * Keywords: ECDH setup, key import, parameter extraction
     * Used for: Initializing ECDH with peer's public key
     */
    public static KeyPair setupECDH(byte[] publicKeyBytes) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        ECPublicKey theirKey = (ECPublicKey) KeyFactory.getInstance("EC")
                .generatePublic(keySpec);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(theirKey.getParams());
        return kpg.generateKeyPair();
    }

    /**
     * Performs ECDH key agreement
     * Keywords: ECDH protocol, key agreement, shared secret
     * Used for: Efficient shared secret generation using elliptic curves
     */
    public static byte[] performECDH(PrivateKey myPrivateKey, PublicKey theirPublicKey) throws Exception {
        KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
        ecdh.init(myPrivateKey);
        ecdh.doPhase(theirPublicKey, true);
        return ecdh.generateSecret();
    }

    /**
     * Derives cryptographic key from password using PBKDF2
     * Keywords: password-based key derivation, salt, iterations
     * Used for: Securely converting passwords into cryptographic keys
     */
    public static SecretKey deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec specs = new PBEKeySpec(password.toCharArray(), salt, 10000, 128);
        return pbkdf.generateSecret(specs);
    }

    /**
     * Performs hybrid encryption (RSA + AES)
     * Keywords: hybrid cryptosystem, session key, key encapsulation
     * Used for: Combining advantages of symmetric and asymmetric encryption
     */
    public static HybridCipherResult hybridEncrypt(PublicKey rsaKey, byte[] plainText) throws Exception {
        Key sessionKey = generateAESKey();
        Cipher aesCipher = Cipher.getInstance(AES_GCM);
        aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        byte[] ciphertext = aesCipher.doFinal(plainText);
        Cipher rsaCipher = Cipher.getInstance(RSA_OAEP);
        rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKey);
        byte[] encryptedKey = rsaCipher.doFinal(sessionKey.getEncoded());

        HybridCipherResult result = new HybridCipherResult();
        result.encryptedKey = encryptedKey;
        result.iv = aesCipher.getIV();
        result.ciphertext = ciphertext;
        return result;
    }

    /**
     * Generates cryptographically secure random bytes
     * Keywords: secure random, entropy source, random generation
     * Used for: Creating IVs, nonces, salts, and other random values
     */
    public static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    /**
     * Creates SHA-256 hash of message
     * Keywords: hash function, message digest, SHA-256
     * Used for: Creating fixed-length message digests
     */
    public static byte[] hash(byte[] message) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(message);
    }

    /**
     * Performs constant-time comparison of byte arrays
     * Keywords: timing attacks, secure comparison, constant time
     * Used for: Securely comparing sensitive values like MACs
     */
    public static boolean compareBytes(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /**
     * Processes large data in chunks for encryption/decryption
     * Keywords: streaming, memory efficient, large files
     * Used for: Handling data too large to fit in memory
     */
    public static byte[] processLargeFile(InputStream inputStream, Cipher cipher) throws Exception {
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            cipher.update(buffer, 0, bytesRead);
        }
        return cipher.doFinal();
    }

    /**
     * Converts hex string to byte array
     * Keywords: hex conversion, string parsing, bytes
     * Used for: Converting hexadecimal strings to binary data
     */
    public static byte[] fromHex(String hex) {
        byte[] binary = new byte[hex.length() / 2];
        for(int i = 0; i < binary.length; i++) {
            binary[i] = (byte)Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        }
        return binary;
    }

    /**
     * Converts byte array to hex string
     * Keywords: hex encoding, byte conversion, string representation
     * Used for: Converting binary data to readable hex format
     */
    public static String toHex(byte[] array) {
        StringBuilder sb = new StringBuilder();
        for (byte b : array) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}








//https://github.com/lem-course/isp-secrecy.git


// A1AESInCBCMode.java
package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * AES in CBC mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AESInCBCMode {
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
                    final Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    IvParameterSpec iv = new IvParameterSpec(new byte[16]);

                    final byte[] pt = message.getBytes();

                    encrypt.init(Cipher.ENCRYPT_MODE, key, iv);
                    final byte[] cipherText = encrypt.doFinal(pt);

                    send("bob", iv.getIV());
                    send("bob", cipherText);

                    IvParameterSpec ivSpec = new IvParameterSpec(receive("bob"));
                    Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
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
                    Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    aesCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

                    byte[] plaintext = aesCipher.doFinal(cipherText);

                    System.out.println("Bob received: " + new String(plaintext));

                    final Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");

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












// A2AESInCTRMode.java
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















//A3ChaCha20.java
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














//A4ExhaustiveSearch.java
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















//AgentCommunication.java
package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

/**
 * A communication channel is implemented with thread-safe blocking queue.
 * <p/>
 * Both agents are implemented by extending the Agents class,
 * creating anonymous class and overriding #execute().
 * <p/>
 * Both agents are started at the end of the main method definition below.
 */
public class AgentCommunication {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() {
                final byte[] payload = "Hi, Bob, this is Alice.".getBytes();
                send("bob", payload);
                final byte[] received = receive("bob");
                print("Got '%s', converted to string: '%s'", hex(received), new String(received));
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() {
                send("alice", "Hey Alice, Bob here.".getBytes());
                print("Got '%s'", new String(receive("alice")));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}














//SymmetricCipherExample.java
package isp.secrecy;

import fri.isp.Agent;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.SecureRandom;

/**
 * EXERCISE:
 * - Study the example
 * - Test different ciphers
 *
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class SymmetricCipherExample {
    public static void main(String[] args) throws Exception {
        final String message = "Hi Bob, this is Alice.";
        System.out.println("[MESSAGE] " + message);

        // STEP 1: Alice and Bob agree upon a cipher and a shared secret key
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        final byte[] pt = message.getBytes();
        System.out.println("[PT] " + Agent.hex(pt));

        //  STEP 2: Create a cipher, encrypt the PT and, optionally, extract cipher parameters (such as IV)
        final Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        final byte[] cipherText = encrypt.doFinal(pt);

        // STEP 3: Print out cipher text (in HEX) [this is what an attacker would see]
        System.out.println("[CT] " + Agent.hex(cipherText));

        /*
         * STEP 4.
         * The receiver creates a Cipher object, defines the algorithm, the secret key and
         * possibly additional parameters (such as IV), and then decrypts the cipher text
         */
        final Cipher decrypt = Cipher.getInstance("AES");
        decrypt.init(Cipher.DECRYPT_MODE, key);
        final byte[] dt = decrypt.doFinal(cipherText);
        System.out.println("[PT] " + Agent.hex(dt));

        // Todo: What happens if the key is incorrect? (Try with RC4 or AES in CTR mode)

        // STEP 5: Create a string from a byte array
        System.out.println("[MESSAGE] " + new String(dt));
    }
}


















//https://github.com/lem-course/isp-integrity.git
/* 
We will be using Java Cryptography Architecture API to provide integrity. We cover the following topics:

Message Authentication Codes
Message digests
ECBC-MAC and HMAC
Collision resistance, length-extension attacks, timing attacks
Repository: https://github.com/lem-course/isp-integrity.git
*/



//A1AgentCommunicationHMAC.java
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














//HMACExample.java
package isp.integrity;

import fri.isp.Agent;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HMACExample {
    public static void main(String[] args) throws Exception {

        final String message = "We would like to provide data integrity for this message.";

        /*
         * STEP 1.
         * Select HMAC algorithm and get new HMAC object instance.
         * Standard Algorithm Names
         * http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
         */
        final Mac alice = Mac.getInstance("HmacSHA256");

        /*
         * STEP 1.
         * Alice and Bob agree upon a shared secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        /*
         * STEP 3.
         * Initialize HMAC and provide shared secret session key. Create an HMAC tag.
         */
        alice.init(key);
        final byte[] tag1 = alice.doFinal(message.getBytes(StandardCharsets.UTF_8));

        /*
         * STEP 4.
         * Print out HMAC.
         */
        final String messageHmacAsString = Agent.hex(tag1);
        System.out.println("HMAC: " + messageHmacAsString);

        /*
         * STEP 5.
         * Bob verifies the tag.
         */
        final Mac bob = Mac.getInstance("HmacSHA256");
        bob.init(key);
        final byte[] tag2 = bob.doFinal(message.getBytes(StandardCharsets.UTF_8));

        // Is the mac correct?

        // Never compare MACs this way
        System.out.println(verify1(tag1, tag2));

        // Better
        System.out.println(verify2(tag1, tag2));

        // Even better
        System.out.println(verify3(tag1, tag2, key));

        // The best
        System.out.println(MessageDigest.isEqual(tag1, tag2));
    }

    public static boolean verify1(byte[] tag1, byte[] tag2) {
        /*
            FIXME: This is insecure
            - The comparison is done byte by byte
            - The comparator returns false immediately after the first inequality of bytes is found
            (Use CTRL+click and see how the  Arrays.equals() is implemented)
         */
        return Arrays.equals(tag1, tag2);
    }

    public static boolean verify2(byte[] tag1, byte[] tag2) {
        /*
            FIXME: Defense #1

            The idea is to compare all bytes

            Important: A "smart" compiler may try to optimize this code
            and end the loop prematurely and thus work against you ...
         */

        if (tag1 == tag2)
            return true;
        if (tag1 == null || tag2 == null)
            return false;

        int length = tag1.length;
        if (tag2.length != length)
            return false;

        // This loop never terminates prematurely
        byte result = 0;
        for (int i = 0; i < length; i++) {
            result |= tag1[i] ^ tag2[i];
        }
        return result == 0;
    }

    public static boolean verify3(byte[] tag1, byte[] tag2, Key key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        /*
            FIXME: Defense #2

            The idea is to hide which bytes are actually being compared
            by MAC-ing the tags once more and then comparing those tags
         */
        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        final byte[] tagtag1 = mac.doFinal(tag1);
        final byte[] tagtag2 = mac.doFinal(tag2);

        return Arrays.equals(tagtag1, tagtag2);
    }

}












//MessageDigestExample.java
package isp.integrity;

import fri.isp.Agent;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MessageDigestExample {

    public static void main(String[] args) throws NoSuchAlgorithmException {

        final String message = "We would like to provide data integrity.";

        /*
         * STEP 1.
         * Select Message Digest algorithm and get new Message Digest object instance
         * http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
         */
        final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");

        /*
         * STEP 2.
         * Create new hash using message digest object.
         */
        final byte[] hashed = digestAlgorithm.digest(message.getBytes(StandardCharsets.UTF_8));

        /*
         * STEP 4: Print out hash. Note we have to convert a byte array into
         * hexadecimal string representation.
         */
        final String hashAsHex = Agent.hex(hashed);
        System.out.println(hashAsHex);
    }
}




























/* 
Authenticated Encryption and CCA security
public key encryption
AES-GCM and ChaCha20-Poly1305
CPA and CCA security for public-key systems
Trapdoor functions and permutations
RSA system, PKCS1, OAEP
Code templates: https://github.com/lem-course/isp-ae-pke.git*/




//A1AgentCommunicationGCM.java
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



















//A2AgentCommunicationPublicSpace.java
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











//A3AgentCommunicationRSA.java
package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class A3AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final String algorithm = "RSA/ECB/OAEPPadding";


        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                final String message = "Just testing stuff, Bob, Alice.";
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);


                final Cipher rsaEnc = Cipher.getInstance(algorithm);
                rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                final byte[] ct = rsaEnc.doFinal(pt);

                System.out.println("CT: " + Agent.hex(ct));
                send("bob", ct);

                /*
                - Create an RSA cipher and encrypt a message using Bob's PK;
                - Send the CT to Bob;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] al_msg = receive("alice");
                System.out.println("BOB_CT: " + al_msg);

                final Cipher rsaDec = Cipher.getInstance(algorithm);
                rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                final byte[] decryptedText = rsaDec.doFinal(al_msg);

                System.out.println("PT: " + Agent.hex(decryptedText));
                final String message2 = new String(decryptedText, StandardCharsets.UTF_8);
                System.out.println("Message: " + message2);


                /*
                - Take the incoming message from the queue;
                - Create an RSA cipher and decrypt incoming CT using Bob's SK;
                - Print the message;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}















//GCMExample.java
package isp;

import fri.isp.Agent;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;

/**
 * An example of using the authenticated encryption cipher.
 * <p>
 * During the encryption, the Galois-Counter mode automatically
 * creates a MAC and verifies it during the decryption.
 * <p>
 * What happens, if the cipher text gets modified?
 * What happens, if the IV gets modified?
 * What happens, if the key is incorrect?
 */
public class GCMExample {
    public static void main(String[] args) throws Exception {
        // shared key
        final SecretKey sharedKey = KeyGenerator.getInstance("AES").generateKey();

        // the payload
        final String message = "this is my message";
        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
        System.out.printf("MSG: %s%n", message);
        System.out.printf("PT:  %s%n", Agent.hex(pt));

        // encrypt
        final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
        alice.init(Cipher.ENCRYPT_MODE, sharedKey);
        final byte[] ct = alice.doFinal(pt);
        System.out.printf("CT:  %s%n", Agent.hex(ct));

        // send IV
        final byte[] iv = alice.getIV();
        System.out.printf("IV:  %s%n", Agent.hex(iv));

        // decrypt
        final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
        // the length of the MAC tag is either 128, 120, 112, 104 or 96 bits
        // the default is 128 bits
        final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
        bob.init(Cipher.DECRYPT_MODE, sharedKey, specs);
        final byte[] pt2 = bob.doFinal(ct);
        System.out.printf("PT:  %s%n", Agent.hex(pt2));
        System.out.printf("MSG: %s%n", new String(pt2, StandardCharsets.UTF_8));
    }
}












//RSA_nopadding_newModulus.java
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.Cipher;

public class RSAExample {
    public static void main(String[] args) throws Exception {
        // Define RSA cipher specifications
        String algorithm = "RSA/ECB/NoPadding";
        
        // Example message
        String message = "I would like to keep this text confidential, Bob. Kind regards, Alice.";
        byte[] pt = message.getBytes(StandardCharsets.UTF_8);
        System.out.println("Message: " + message);
        System.out.println("PT: " + Agent.hex(pt));

        // Generate RSA key pair with a different modulus size
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024); // Example modulus size
        KeyPair bobKP = kpg.generateKeyPair();

        // Encrypt the plaintext
        Cipher rsaEnc = Cipher.getInstance(algorithm);
        rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
        byte[] ct = rsaEnc.doFinal(pt);
        System.out.println("CT: " + Agent.hex(ct));

        // Decrypt the ciphertext
        Cipher rsaDec = Cipher.getInstance(algorithm);
        rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
        byte[] decryptedText = rsaDec.doFinal(ct);
        System.out.println("PT: " + Agent.hex(decryptedText));
        String message2 = new String(decryptedText, StandardCharsets.UTF_8);
        System.out.println("Message: " + message2);
    }
}











//RSAExample.java
package isp;

import fri.isp.Agent;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Assignments:
 * - Find out how to manually change the RSA modulus size
 * - Set padding to NoPadding. Encrypt a message and decrypt it. Is the
 * decrypted text the same as the original plaint text? Why?
 */
public class RSAExample {

    public static void main(String[] args) throws Exception {
        // Set RSA cipher specs:
        //  - Set mode to ECB: each block is encrypted independently
        //  - Set padding to OAEP (preferred mode);
        //    alternatives are PKCS1Padding (the default) and NoPadding ("textbook" RSA)
        final String algorithm = "RSA/ECB/OAEPPadding";
        final String message = "I would like to keep this text confidential, Bob. Kind regards, Alice.";
        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

        System.out.println("Message: " + message);
        System.out.println("PT: " + Agent.hex(pt));

        // STEP 1: Bob creates his public and private key pair.
        // Alice receives Bob's public key.
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        final KeyPair bobKP = kpg.generateKeyPair();

        // STEP 2: Alice creates Cipher object defining cipher algorithm.
        // She then encrypts the clear-text and sends it to Bob.
        final Cipher rsaEnc = Cipher.getInstance(algorithm);
        rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
        final byte[] ct = rsaEnc.doFinal(pt);

        // STEP 3: Display cipher text in hex. This is what an attacker would see,
        // if she intercepted the message.
        System.out.println("CT: " + Agent.hex(ct));

        // STEP 4: Bob decrypts the cipher text using the same algorithm and his private key.
        final Cipher rsaDec = Cipher.getInstance(algorithm);
        rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
        final byte[] decryptedText = rsaDec.doFinal(ct);

        // STEP 5: Bob displays the clear text
        System.out.println("PT: " + Agent.hex(decryptedText));
        final String message2 = new String(decryptedText, StandardCharsets.UTF_8);
        System.out.println("Message: " + message2);
    }
}
















/*
 Key agreement protocols:

Trusted Third Parties
Diffie-Hellman
Public-key cryptography
Digital signatures
Extra: Key derivation
Code templates: https://github.com/lem-course/isp-keyagreement.git
*/



//A1AgentCommunicationKeyExchange.java
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

/*
 * Implement a key exchange between Alice and Bob using public-key encryption.
 * Once the shared secret is established, send an encrypted message from Alice to Bob using
 * AES in GCM.
 */
public class A1AgentCommunicationKeyExchange {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(256);

                final KeyPair keyPair = kpg.generateKeyPair();

                send("bob", keyPair.getPublic().getEncoded());
                //print("My contribution to ECDH: %s", hex(keyPair.getPublic().getEncoded()));

                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("bob"));
                final ECPublicKey bobPK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);

                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(bobPK, true);

                final byte[] sharedSecret = dh.generateSecret();
                //print("Shared secret: %s", hex(sharedSecret));

                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, aesKey);

                final byte[] ct = aes.doFinal("Hey Bob, did you get the message!".getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aes.getIV();

                send("bob", iv);
                send("bob", ct);

                //print("I'm, done!");
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("alice"));
                final ECPublicKey alicePK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);

                final ECParameterSpec dhParamSpec = alicePK.getParams();

                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(dhParamSpec);
                final KeyPair keyPair = kpg.generateKeyPair();
                send("alice", keyPair.getPublic().getEncoded());

                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(alicePK, true);

                final byte[] sharedSecret = dh.generateSecret();
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                final byte[] iv = receive("alice");
                final byte[] ct = receive("alice");
                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
                final byte[] pt = aes.doFinal(ct);

                print(new String(pt, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}












//AgentCommunicationDH.java
package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.X509EncodedKeySpec;

public class AgentCommunicationDH {
    public static void main(String[] args) {

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
                kpg.initialize(2048);

                // Generate key pair
                final KeyPair keyPair = kpg.generateKeyPair();

                // send "PK" to bob ("PK": A = g^a, "SK": a)
                send("bob", keyPair.getPublic().getEncoded());
                print("My contribution: A = g^a = %s",
                        hex(keyPair.getPublic().getEncoded()));

                // get PK from bob
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("bob"));
                final DHPublicKey bobPK = (DHPublicKey) KeyFactory.getInstance("DH")
                        .generatePublic(keySpec);

                // Run the agreement protocol
                final KeyAgreement dh = KeyAgreement.getInstance("DH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(bobPK, true);

                // generate a shared AES key
                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: g^ab = B^a = %s", hex(sharedSecret));

                // By default the shared secret will be 32 bytes long,
                // but our cipher requires keys of length 16 bytes
                // IMPORTANT: It is safer to not create the session key directly from
                // the shared secret, but derive it using key derivation function
                // (will be covered later)
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret,
                        0, 16, "AES");

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, aesKey);

                final byte[] ct = aes.doFinal("Hey Bob!".getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aes.getIV();

                send("bob", iv);
                send("bob", ct);

                print("I'm, done!");
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // get PK from alice
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(
                        receive("alice"));
                final DHPublicKey alicePK = (DHPublicKey) KeyFactory.getInstance("DH")
                        .generatePublic(keySpec);

                final DHParameterSpec dhParamSpec = alicePK.getParams();

                // create your own DH key pair
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
                kpg.initialize(dhParamSpec);
                final KeyPair keyPair = kpg.generateKeyPair();
                send("alice", keyPair.getPublic().getEncoded());
                print("My contribution: B = g^b = %s",
                        hex(keyPair.getPublic().getEncoded()));

                final KeyAgreement dh = KeyAgreement.getInstance("DH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(alicePK, true);

                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: g^ab = A^b = %s", hex(sharedSecret));
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                final byte[] iv = receive("alice");
                final byte[] ct = receive("alice");
                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
                final byte[] pt = aes.doFinal(ct);

                print("I got: %s", new String(pt, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}













//AgentCommunicationECDH.java
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

public class AgentCommunicationECDH {
    public static void main(String[] args) {

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(256);

                // Generate key pair
                final KeyPair keyPair = kpg.generateKeyPair();

                // send "PK" to bob ("PK": A = g^a, "SK": a)
                send("bob", keyPair.getPublic().getEncoded());
                print("My contribution to ECDH: %s", hex(keyPair.getPublic().getEncoded()));

                // get PK from bob
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("bob"));
                final ECPublicKey bobPK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);

                // Run the agreement protocol
                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(bobPK, true);

                // generate a shared AES key
                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: %s", hex(sharedSecret));

                // By default the shared secret will be 32 bytes long,
                // our cipher requires keys of length 16 bytes
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, aesKey);

                final byte[] ct = aes.doFinal("Hey Bob!".getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aes.getIV();

                send("bob", iv);
                send("bob", ct);

                print("I'm, done!");
            }
        });

        env.add(new Agent("bob") {
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

                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(alicePK, true);

                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: %s", hex(sharedSecret));
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                final byte[] iv = receive("alice");
                final byte[] ct = receive("alice");
                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
                final byte[] pt = aes.doFinal(ct);

                print("I got: %s", new String(pt, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}













//digital signatures

//A2AgentCommunicationSignature.java
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









//KeyDerivation.java
package isp.signatures;

import fri.isp.Agent;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;

public class KeyDerivation {
    public static void main(String[] args) throws Exception {
        // password from which the key will be derived
        final String password = "hunter2";

        // a random, public and fixed string
        final byte[] salt = "89fjh3409fdj390fk".getBytes(StandardCharsets.UTF_8);

        // use PBKDF2 with the password, salt, and number of iterations and required bits
        final SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        final KeySpec specs = new PBEKeySpec(password.toCharArray(), salt,
                10000, 128);
        final SecretKey generatedKey = pbkdf.generateSecret(specs);

        System.out.printf("key = %s%n", Agent.hex(generatedKey.getEncoded()));
        System.out.printf("len(key) = %d bytes%n", generatedKey.getEncoded().length);

        final String message = "Hello World!";

        // for example, use the derived key as the HMAC key
        final Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));
        System.out.printf("HMAC[%s] = %s%n", message, Agent.hex(hmac.doFinal(message.getBytes())));

    }
}













//SignatureExampleRSA.java
package isp.signatures;

import fri.isp.Agent;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class SignatureExampleRSA {
    public static void main(String[] args) throws Exception {

        // https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature
        final String signingAlgorithm =
                "SHA256withRSA";
//         "SHA256withDSA";
//        "SHA256withECDSA";
        final String keyAlgorithm =
                "RSA";
//         "DSA";
//         "EC";


        // The message we want to sign
        final String document = "We would like to sign this.";

        /*
         * STEP 1.
         * We create a public-private key pair using standard algorithm names
         * http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
         */
        final KeyPair key = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();

        /*
         * Alice creates Signature object defining Signature algorithm.
         */
        final Signature signer = Signature.getInstance(signingAlgorithm);

        /*
         * We initialize the signature object with
         * - Operation modes (SIGN) and
         * - provides appropriate ***Private*** Key
         */
        signer.initSign(key.getPrivate());

        // Finally, we load the document into the signature object and sign it
        signer.update(document.getBytes(StandardCharsets.UTF_8));
        final byte[] signature = signer.sign();
        System.out.println("Signature: " + Agent.hex(signature));

        /*
         * To verify the signature, we create another signature object
         * and specify its algorithm
         */
        final Signature verifier = Signature.getInstance(signingAlgorithm);

        /*
         * We have to initialize in the verification mode. We only need
         * to know public key of the signer.
         */
        verifier.initVerify(key.getPublic());

        // Check whether the signature is valid
        verifier.update(document.getBytes(StandardCharsets.UTF_8));

        if (verifier.verify(signature))
            System.out.println("Valid signature.");
        else
            System.err.println("Invalid signature.");
    }
}










//SignatureExampleRSAPSS.java

package isp.signatures;

import fri.isp.Agent;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class SignatureExampleRSAPSS {
    public static void main(String[] args) throws Exception {
        final String document = "We would like to sign this.";

        final KeyPair key = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final Signature signer = Signature.getInstance("RSASSA-PSS");
        signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        signer.initSign(key.getPrivate());
        signer.update(document.getBytes(StandardCharsets.UTF_8));
        final byte[] signature = signer.sign();

        System.out.println("Signature: " + Agent.hex(signature));

        final Signature verifier = Signature.getInstance("RSASSA-PSS");
        verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        verifier.initVerify(key.getPublic());
        verifier.update(document.getBytes(StandardCharsets.UTF_8));

        if (verifier.verify(signature))
            System.out.println("Valid signature.");
        else
            System.err.println("Invalid signature.");
    }
}












/*KOLOKVIJ 1
 
please make a 

The Protocol
In this assignment, you will implement a one-sided authenticated key-exchange protocol between Alice and the server. This will be a slightly simplified
variant of a hand-shake protocol that occurs in TLSv1.3 which you use all the time when you browse the web.

Client Alice will establish a connection over an insecure communication channel to the server. Then she will run a one-sided authenticated key-exchange
protocol in which a shared secret will be created to secure subsequent communication.

Initially, the protocol will only authenticate the server while Alice's identity will remain unconfirmed. To also authenticate Alice, the server will send a
password challenge to which Alice will have to correctly respond. When done so, her identity will be confirmed.
Initial setting
Server is using an RSA public-secret key pair denoted as (pk, sk). Alice is assumed to know the public key pk in advance.
Alice does not have a keypair. Instead, she uses a password pwd. Similarly, this password is also known to the server.
In code, define the keypair and the password globaly in the method main(String[]) so that Alice and Server can both access it. However, don't access the
secret key from within the agent Alice: she may only use the public key pk and the password pwd. The server, however, may also use the secret key sk.


Detailed description
The protocol contains the following steps. At the end, you'll find a diagram that provides an overview.
1. Alice begins by initiating the Diffie-Hellman key exchange protocol. Use the Elliptic Curve variant as we did in the labs; a good starting point for
the assignment is the isp-keyagreement project.

Alice creates her secret value a and computes her public value A = ga mod p. (While the notation might suggest the DH protocol is using
the arithmetic modulo prime numbers, use the Elliptic curve variant.)

She then sends the public value A to the server.
2. Similarly, server picks its own secret value band computes its public value B = g mod p. It then receives Alice's public value A, and
combines it with its own secret value to obtain the Diffie-Hellman shared secret.
This value is then immediately hashed with SHA-256 and from the result an AES symmetric key is derived: k = H(A mod p). Since the hash
will have 32-bytes, and the key requires only 16-bytes, take the first 16-bytes as the key.
Next, the server concatenates Alice's public value A and its own public value B and signs the result using RSA signing algorithm using SHA-256
and its secret key sk: o = S(sk, A||B).

While the pair B, o should be sufficient to prove to Alice that the server is genuine, the server cannot be sure whether Alice is really Alice - it
might be someone impersonating her.
So the server issues a password-based challenge to Alice: the server will pick a random 256-bit (32-byte) value chall, symmetrically encrypt it
with the just derived symmetric key k using AES in GCM mode and send its encrypted value Cchall < E(k, chall) to Alice, along with the DH
public value B and the signature o.
3. Alice receives the messages and immediately verifies the signature o. If the signature fails to verify, the protocol is aborted.
If the signature verifies, she computes the secret key k like the server: k = H(Bª mod p). She then uses AES-GCM to decrypt the challenge:
chall <- D(k, Cchall)
Next, she creates the response by appending the challenge chall to the password pwd and hashing the result with SHA-256:
resp = H(pwd||chall).
Finally she encrypts the response Cresp <- E(k, resp) and sends the Cresp to the server. She is now done.
4. Server receives the ciphertext Cresp and decrypts it: resp <- D(k, Cresp)
Finally, the server verifies the response: it hashes the concatenation of Alices password and the challenge value H(pwd||chall) and compares
the result with the decrypted response resp: if they match, Alice is authenticated. If not, the protocol is aborted.

If the protocol terminates succesfully, both Alice and the server are authenticated and they have a shared secret key k which can be used to
symmetrically encrypt and authenticate data.


 */

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












/*
 * Information Security & Privacy: Midterm 1 Exercises
 * 
 * Exercise 1: MAC Tag Computation and Verification
 * Implement token-based access control in Lock. Alice sends a token, and the Lock verifies it. If verification succeeds, print SUCCESS; otherwise, print FAILURE.
 * 
 * Exercise 2: Token Transfer from Server to Lock
 * As the Server, forward the token to the Lock. Compute the MAC tag using HMAC-SHA256 and send it alongside the token. Use PBKDF2 with HMAC-SHA256 for key derivation.
 * 
 * Exercise 3: Symmetric Confidentiality and Integrity with Token Production
 * Provide symmetric confidentiality and integrity for communication between Alice and the Server. Generate 1000 tokens by repeatedly hashing a secret and upload the last token to the Server.
 * 
 * Exercise 4: Mutually Authenticate Channel and Generate Shared Secret
 * Authenticate the channel between Alice and the Server using RSA public-private key pairs. Implement forward-secure key-agreement to ensure recorded messages cannot be decrypted if keys are later compromised.
 * 
 * Exercise 5: Token Verification Process
 * Generate tokens by applying SHA256 repeatedly to a secret. Transfer the token from Server to Lock with a computed MAC tag. During access attempts, the Lock verifies the token using Lamport's procedure.
 * 
 * Exercise 6: Protocol Overview Implementation
 * Implement Leslie Lamport's one-time-password scheme using SHA256 for NFC-capable phone access control. The procedure includes token generation, upload, transfer to Lock, and access attempts.
 * 
 * Exercise 7: RSA Example Implementation
 * Change RSA modulus size and set padding to NoPadding. Encrypt and decrypt a message, then observe and explain the results.
 */

// M K
 package isp.kolokvij;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.EventListener;

public class Midterm_MK {

    public static byte[] mac(byte[] payload, String password, byte[] salt) throws Exception {

        SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1000, 128);
        SecretKey derivedKey = pbkdf.generateSecret(spec);

        Key key = new SecretKeySpec(derivedKey.getEncoded(), "HmacSHA256");

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        return mac.doFinal(payload);
    }

    public static boolean verify(byte[] payload, byte[] tag, String password, byte[] salt) throws Exception {
        byte[] expectedTag = mac(payload, password, salt);

        if (Arrays.equals(expectedTag, tag)) {
            //System.out.println("SUCCESS");
            return true;
        }
        else {
            //System.out.println("FAILURE");
            return false;
        }
    }

    public static byte[] hash(int times, byte[] payload) throws Exception{
        final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
        byte[] result = payload;

        for (int i = 0; i < times; i++) {
            result = digestAlgorithm.digest(result);
        }

        return result;
    }

    public static void main(String[] args) throws Exception {

        final SecretKey sharedKey = KeyGenerator.getInstance("AES").generateKey();
        final SecretKey sharedKeyServerLock = KeyGenerator.getInstance("AES").generateKey();


        Environment env = new Environment();

        byte[] secret = new byte[32];  // 32 bytes for SHA256
        new SecureRandom().nextBytes(secret);

        String SHARED_PASSWORD = "12345678";

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);

        // Generate key pair
        final KeyPair keyPairServer = kpg.generateKeyPair();

        final KeyPair keyPairAlice = kpg.generateKeyPair();

        env.add(new Agent("alice") {
            private String password = "test";
            public void task() throws Exception {

                byte[] salt = new byte[16];
                new SecureRandom().nextBytes(salt);
                byte[] currentToken = secret;

                byte[] token = hash(1000, password.getBytes());

                byte[][] tokenChain = new byte[1001][]; // Store all tokens

                for (int i = 0; i <= 1000; i++) {
                    currentToken = hash(1, currentToken); // Hash the token
                    tokenChain[i] = currentToken;         // Store in the chain
                }

                //byte[] tag = mac(token, password, salt);

                System.out.println(Arrays.toString(token));

                final Cipher cp = Cipher.getInstance("AES/GCM/NoPadding");
                cp.init(Cipher.ENCRYPT_MODE, sharedKey);
                final byte[] ct = cp.doFinal(token);
                final byte[] iv = cp.getIV();

                send("server", keyPairAlice.getPublic().getEncoded());
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("server"));
                final ECPublicKey bobPK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);

                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPairAlice.getPrivate());
                dh.doPhase(bobPK, true);


                send("server", ct);
                send("server", iv);
            }
        });
        env.add(new Agent("server") {
            public void task() throws Exception {

                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("alice"));
                final ECPublicKey alicePK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);

                final ECParameterSpec dhParamSpec = alicePK.getParams();

                // create your own DH key pair
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(dhParamSpec);
                final KeyPair keyPair = kpg.generateKeyPair();
                send("alice", keyPair.getPublic().getEncoded());

                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(alicePK, true);


                // Generate salt for MAC computation
                byte[] salt = new byte[16];
                SecureRandom.getInstanceStrong().nextBytes(salt);

                // Receive encrypted token and IV from Alice
                final byte[] ct_r = receive("alice");
                final byte[] iv_r = receive("alice");

                // Decrypt token using AES-GCM
                final Cipher server = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec specs = new GCMParameterSpec(128, iv_r);
                server.init(Cipher.DECRYPT_MODE, sharedKey, specs);
                final byte[] pt2 = server.doFinal(ct_r);  // Decrypted token (plaintext)

                // Compute MAC tag using the shared password and salt
                byte[] x = mac(pt2, SHARED_PASSWORD, salt);

                // Send the token, MAC tag, and salt to the lock
                send("lock", pt2);  // Send the plaintext token
                send("lock", x);    // Send the computed MAC tag
                send("lock", salt); // Send the salt for verification
            }
        });


        env.add(new Agent("lock") {
            public void task() throws Exception {
                //byte[] token = receive("alice");
                byte[] token_server = receive("server");
                byte[] tag_server = receive("server");
                byte[] salt_server = receive("server");

                byte[] storedToken = null;

                if(verify(token_server, tag_server, SHARED_PASSWORD, salt_server)) {
                    System.out.println("SERVER TOKEN VERIFIED");
                    storedToken = token_server;

                }
                else {
                    System.out.println("SERVER TOKEN NOT VERIFIED");
                }

                byte[] receivedToken = receive("alice");

                byte[] hashedToken = hash(1, receivedToken);
                if (Arrays.equals(hashedToken, storedToken)) {
                    System.out.println("ACCESS GRANTED");
                    storedToken = receivedToken;
                } else {
                    System.out.println("ACCESS DENIED");
                }
            }
        });



        env.connect("alice", "server");
        env.connect("server", "lock");
        env.connect("alice", "lock");


        env.start();
    }
}





// Z F
package isp.handson;

import java.nio.charset.StandardCharsets;
import java.security.spec.InvalidKeySpecException;
import java.security.*;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.security.Key;


import java.security.KeyPair;
import java.security.KeyPairGenerator;


import fri.isp.Agent;
import fri.isp.Environment;


import java.security.SecureRandom;

public class Midterm {
        public static String pwd_S_L = "PWD_SERVER_LOCK";

        public static void main(String[] args) throws Exception {
        Environment env = new Environment();

        //key for sending hash
        final Key key = KeyGenerator.getInstance("AES").generateKey();
        //the symetric key to be sent over rsa
        final Key key2 = KeyGenerator.getInstance("AES").generateKey();
        //Define the public-secret key pairs globally in the main method.
        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            env.add(new Agent("alice") {
            public void task() throws Exception {
                // sending token to server, so he can open the lock
                final String text = "TOKEN.";
                final byte[] salt = new byte[16];
                new SecureRandom().nextBytes(salt);
                print("Salt: %s", hex(salt));
                final byte[] tag = mac(text.getBytes(StandardCharsets.UTF_8), "PWD_A_S", salt);
                send("server", text.getBytes(StandardCharsets.UTF_8));
                send("server", tag);
                send("server", salt);

                // sending hash with authentification and encryption
                final String texty = "I hope you get this message intact and in secret. Kisses, Alice." ;
                byte[] pt = texty.getBytes(StandardCharsets.UTF_8);
                //rabimo poslat hash
                pt = hash(1000, pt);
                final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                alice.init(Cipher.ENCRYPT_MODE, key);
                byte[] ct = alice.doFinal(pt);
                final byte[] iv = alice.getIV();
                send("server", ct);
                send("server", iv);


                // sending key with rsa NALOGA 4
                // pise shared secret pa forward secrecy,
                // najprej pise da naredis z rsa.  potem pa diffie hellman,  ker edino ta da forward secrecy
                //prav bi bilo da bi z diffie hellman naredil
                final byte[] key2Bytes = key2.getEncoded();
                final Cipher rsaEnc = Cipher.getInstance("RSA");
                rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                ct = rsaEnc.doFinal(key2Bytes);
                print("PT_RSA: " + Agent.hex(key2.getEncoded()));
                send("server", ct);

                /*
                Ostale naloge
                 Naloga5/6
                 token 1000krat hasham z sha256
                 privat ključ nrdim,
                 token pošljem z hmac do serverja
                 send same hmac to lock
                 lock preracuna svoj hmac z istim private keyom
                 pol pa primerja če je isti
                če  nocemo da ma svoj private, ima lahko lock samo shranjen svoj  hash code
                */




            }
        });
        env.add(new Agent("server") {
            public void task() throws Exception {

                // receiving token from alice and sending it to lock
                final byte[] receivedTextBytes = receive("alice");
                byte[] taggy = receive("alice");
                final byte[] salt = receive("alice");
                if (verify(receivedTextBytes, taggy, "PWD_A_S", salt)) {
                    print("SUCCESS:  -- Integrity verified for Alice's message - " + new String(receivedTextBytes, StandardCharsets.UTF_8));
                } else {
                    print("FAILURE -- Integrity check failed for Alice's message!");
                }
                taggy = mac(receivedTextBytes, pwd_S_L, salt);
                send("lock", receivedTextBytes);
                send("lock", taggy);
                send("lock", salt);



                // receiving hash from alice and decrypting it
                final byte[] text_rec = receive("alice");
                final byte[] iv_rec = receive("alice");
                final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec specs = new GCMParameterSpec(128, iv_rec);
                bob.init(Cipher.DECRYPT_MODE, key, specs);
                final byte[] pt2 = bob.doFinal(text_rec);
                print("SUCCESS: Hash of message: %s%n", new String(pt2, StandardCharsets.UTF_8));


                // receive key with rsa
                final byte[] al_msg = receive("alice");
                print("SERVER_CT: " + al_msg);
                final Cipher rsaDec = Cipher.getInstance("RSA");
                rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                final byte[] decryptedText = rsaDec.doFinal(al_msg);
                print("PT_RSA: " + Agent.hex(decryptedText));
                /* */
            }
        });
        env.add(new Agent("lock") {
            public void task() throws Exception {

                final byte[] receivedTextBytes = receive("server");
                final byte[] taggy = receive("server");
                final byte[] salt = receive("server");

                if (verify(receivedTextBytes, taggy, pwd_S_L, salt)) {
                    print("SUCCESS:  -- Integrity verified for Alice's message - " + new String(receivedTextBytes, StandardCharsets.UTF_8));
                } else {
                    print("FAILURE -- Integrity check failed for Alice's message!");
                }




            }
        });

        env.connect("alice", "server");
        env.connect("alice", "lock");
        env.connect("server", "lock");
        env.start();
    }

    /**
     * Verifies the MAC tag.
     *
     * @param payload  the message
     * @param tag      the MAC tag
     * @param password the password form which MAC key is derived
     * @param salt     the salt used to strengthen the password
     * @return true iff. the verification succeeds, false otherwise
     */
    public static boolean verify(byte[] payload, byte[] tag, String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1000, 256);
        SecretKeySpec secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "HmacSHA256");

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);

        byte[] computedTag = mac.doFinal(payload);

        return MessageDigest.isEqual(computedTag, tag);
    }


    /**
     * Computes the MAC tag over the message.
     *
     * @param payload  the message
     * @param password the password form which MAC key is derived
     * @param salt     the salt used to strengthen the password
     * @return the computed tag
     */
    public static byte[] mac(byte[] payload, String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); // password based key
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1000, 256);
        SecretKeySpec secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "HmacSHA256");

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);

        return mac.doFinal(payload);
    }

    /**
     * Hashes the given payload multiple times.
     *
     * @param times   the number of times the value is hashed
     * @param payload the initial value to be hashed
     * @return the final hash value
     */

    public static byte[] hash(int times, byte[] payload) throws Exception {

        final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
        byte[] hashed = digestAlgorithm.digest(payload);
        for (int i = 0; i < times; i++){
            hashed = digestAlgorithm.digest(payload);
        }
        return hashed;
    }



    /**
     * Verifies if the MAC tag is correct and if it was received before the deadline
     *
     * @param token        that was received
     * @param deadline     in UNIX time
     * @param tag          to compare against
     * @param password     used to derive the MAC key
     * @param salt         to increase MAC key's enthropy
     * @param receivedTime UNIX time at which the message was received
     * @return true iff. the mac verifies and the message was received before the deadline
     */
    public static boolean verifyTimed(byte[] token, byte[] deadline, byte[] tag,
                                      String password, byte[] salt, long receivedTime) throws Exception {
        return true;
    }

}

