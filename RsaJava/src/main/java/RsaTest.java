import java.security.*;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class RsaTest {
    private final SecureRandom random = new SecureRandom();
    private Key privKey;
    private Key pubKey;

    public void run() throws Exception {
        genKeys();

        byte[] input = "abc".getBytes();

        Cipher cipher;

        // Encrypt
        //cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        //cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);

        cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey,
                new OAEPParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));

        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: len=" + cipherText.length); //new String(cipherText));

        // Decrypt
        cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + new String(plainText));
    }

    private void loadKeys() {

    }



    private void genKeys() throws NoSuchAlgorithmException {
        // Generate Keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");;
        generator.initialize(2048, random);
        KeyPair pair = generator.generateKeyPair();
        pubKey = pair.getPublic();
        privKey = pair.getPrivate();
    }
}
