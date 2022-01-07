import java.security.*;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class Main {
    private static final SecureRandom random = new SecureRandom();

    public static void main(String[] args) throws Exception {
        // Generate Keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");;
        generator.initialize(2048, random);
        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();
        Key privKey = pair.getPrivate();

        

        byte[] input = "abc".getBytes();

        Cipher cipher;
        
        // Encrypt
        //cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        //cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);

        cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey,
                new OAEPParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT));

        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: len=" + cipherText.length); //new String(cipherText));

        // Decrypt
        cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + new String(plainText));
    }
}
