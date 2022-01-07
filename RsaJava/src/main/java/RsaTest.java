import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import sun.rmi.rmic.iiop.ClassPathLoader;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class RsaTest {
    private final SecureRandom random = new SecureRandom();
    private Key privKey;
    private Key pubKey;

    public void run() throws Exception {
        //genKeys();
        loadKeys();

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

    private void loadKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        
        X509EncodedKeySpec xs = new X509EncodedKeySpec(Base64.decode(Keys.pubkey));
        pubKey = kf.generatePublic(xs);

        PKCS8EncodedKeySpec ps = new PKCS8EncodedKeySpec(Base64.decode(Keys.privkey));
        privKey = kf.generatePrivate(ps);
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
