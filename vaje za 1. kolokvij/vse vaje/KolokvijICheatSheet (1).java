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