package com.example.qrcodescanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class QRCodeDecoder {

    private int signatureLength = 172;

    private static final String ALGORITHM = "RSA";

    private static final String NONE_PADDING = "RSA/None/PKCS1Padding";

    private static final Provider pro = new BouncyCastleProvider();

    private static String publicCheckKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBO71iVLEu7umehJ0HJ5501wW1rSKTL3hkng+WRJZCnQ/3ZWLJrdLdgRRkaQMpzdF+AmqvtioluXjZdyrhLpkRtcAkjgQbBnRnL5zirJydmYZJU8CRSjrrER439hHTD9Zml1y9Pa//NPcfnd9iw6kZSX5rArEzFiKp3hRZGgecYwIDAQAB";

    private static String privateCheckKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAME7vWJUsS7u6Z6EnQcnnnTXBbWtIpMveGSeD5ZElkKdD/dlYsmt0t2BFGRpAynN0X4Caq+2KiW5eNl3KuEumRG1wCSOBBsGdGcvnOKsnJ2ZhklTwJFKOusRHjf2EdMP1maXXL09r/809x+d32LDqRlJfmsCsTMWIqneFFkaB5xjAgMBAAECgYEAm4K/hI5SVkoyO7/QPDzXWoLd9ntTEw8mHhvSwYWLRCrw+ZJfsZ2x0VAboD+fKxqYGYhKYgUB4IBm0OUF3lnJF0CmzWYcPg7QpsNRU2iCp50c6EyGmNItpPQycnTx68xG1RTYE1EXfwAmHDeB9Bbsk87HHdJQqjANnUFeSDPq9/ECQQDelkKO7rZA/KNKmQJZIqGEGWvlMb+5SuHCiVRLT3vqKuaub0Fym1Ey6ngVYN5yZt2tnUV6brfwr+/y3TyQlq0pAkEA3j11Ju32DsAzC4dtmDM4vee8KY7OpnE2dkEGA9K6U8M/R3y3WQEtUC8kqf+m9EXOdiMlB72Ld0N0TojQ+R6iqwJAMcDShdJz6JjQAyeqb7Qe+EEabfOt0EQdrHc34VGV+CS4xXrW3UA8aS4hw12Qu2+k017ZHeHLucAJ2XZ8SDF16QJAE+woe2Proeji6o6qaXF2Dbgfaw5NQih1/GXZ1y/l2ipvmsX4Xbc4S67eN4seeVlkp7yAzk/Ul81pOL0VFrADXwJBAI/2Oq2AcSNOu6QY3JuzU4kN1mjKGDkBqmV3nHev9bp7NLyoasqzg8xo9lvuYjPpo47JXPgpH+CXXkLTTmqk/m8=";


    private static PublicKey publicKey;

    static {
        try {
            publicKey = getPublicRSAKey(publicCheckKey);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    private static PrivateKey privateKey;

    static {
        try {
            privateKey = getPrivateRSAKey(privateCheckKey);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    public QRCodeDecoder() throws InvalidKeySpecException {
    }

    public static String decodeQRCodeValue(String qrCodeData) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {

        String[] values = qrCodeData.split(" ");

        System.out.println(values.length);

        String signature = values[values.length - 1];

        String encryptedPass = values[values.length - 2];

        String valueToCheckSignature = qrCodeData.substring(0, qrCodeData.length() - signature.length() - 1);

        boolean isSignatureCorrect = verify(valueToCheckSignature, signature, publicKey, "SHA256withRSA");

        if (isSignatureCorrect) {
            String pass = decryptToString(encryptedPass, privateKey);
            return "First 4 and last 4 numbers of card: " + values[1] + "\n" +
                    "Time of operation: " + values[2] + "\n" +
                    "Amount: " + values[3] + "\n" +
                    "Type of operation: " + values[4] + "\n" +
                    "One time password: " + pass;
        }

        return "Error";
    }

    public static boolean verify(String data, String sign, PublicKey publicKey, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(publicKey);
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        return signature.verify(Base64.decode(sign));
    }

    private static byte[] decrypt(byte[] text, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(NONE_PADDING, pro);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(text);
    }

    private static String decryptToString(byte[] text, Key key) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return new String(decrypt(text, key));
    }

    public static String decryptToString(String text, Key key) throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException {
        byte[] en = Base64.decode(text);
        return decryptToString(en, key);
    }

    public static PrivateKey getPrivateRSAKey(String key) throws InvalidKeySpecException {
        return bytesToPrivateKey(org.bouncycastle.util.encoders.Base64.decode(key));
    }

    private static PublicKey getPublicRSAKey(String key) throws InvalidKeySpecException {
        return bytesToPublicKey(org.bouncycastle.util.encoders.Base64.decode(key));
    }

    private static PrivateKey bytesToPrivateKey(byte[] bytes) throws InvalidKeySpecException {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM, pro);
            return kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            //
        }
        return null;
    }

    private static PublicKey bytesToPublicKey(byte[] bytes) throws InvalidKeySpecException {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM, pro);
            return kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            // Can't happen
        }
        return null;
    }

}
