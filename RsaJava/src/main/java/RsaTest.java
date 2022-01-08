import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RsaTest {
    private final SecureRandom random = new SecureRandom();
    private Key privKey;
    private Key pubKey;

    public void run() throws Exception {
        loadKeys();

        test1();
        test2();
        test3();
    }

    private void test1() throws Exception {
        loadKeys();

        String input = "THIS IS TEST TEXT";

        // encrypt
        byte[] cipherText = encrypt(input, MGF1ParameterSpec.SHA512);
        System.out.println("cipher: len=" + cipherText.length); //new String(cipherText));
        System.out.println("cipher(base64): " + Base64.encode(cipherText));

        // Decrypt
        byte[] plain = decrypt(cipherText, MGF1ParameterSpec.SHA512);
        System.out.println("plain : " + new String(plain));
    }

    private void test2() throws Exception {
        byte[] cipherText = Base64.decode(Data.cipherTextOAEPSHA512);
        byte[] plain = decrypt(cipherText, MGF1ParameterSpec.SHA512);

        System.out.println("test2: " + new String(plain));
    }

    private void test3() throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plain = cipher.doFinal(Base64.decode(Data.cipherTextPKCS1));
        System.out.println("test3: " + new String(plain));
    }

    private byte[] encrypt(String plain) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);

        return cipher.doFinal(plain.getBytes());
    }

    private byte[] encrypt(String plain, MGF1ParameterSpec mgf1Spec) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, new OAEPParameterSpec("SHA-512", "MGF1", mgf1Spec, PSource.PSpecified.DEFAULT));

        return cipher.doFinal(plain.getBytes());
    }

    private byte[] decrypt(byte[] cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privKey);

        return cipher.doFinal(cipherText);
    }

    private byte[] decrypt(byte[] cipherText, MGF1ParameterSpec mgf1Spec) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.DECRYPT_MODE, privKey, new OAEPParameterSpec("SHA-512", "MGF1", mgf1Spec, PSource.PSpecified.DEFAULT));

        return cipher.doFinal(cipherText);
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
