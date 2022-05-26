package com.example.qrcodescanner;

import static com.example.qrcodescanner.Security.decryptToString;
import static com.example.qrcodescanner.Security.verify;

import java.io.UnsupportedEncodingException;
import java.security.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class QRCodeDecoder {

    public static int NUMBER_OF_ELEMENTS_IN_QR_CODE = 6;

    public QRCodeDecoder() {}

    public static String decodeQRCodeValue(String qrCodeData) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {

        String[] values = qrCodeData.split(" ");

        if(values.length != NUMBER_OF_ELEMENTS_IN_QR_CODE) {
            return "Not recognizable";
        }

        String signature = values[values.length - 1];
        String encryptedPass = values[values.length - 2];
        String valueToCheckSignature = qrCodeData.substring(0, qrCodeData.length() - signature.length() - 1);
        boolean isSignatureCorrect = verify(valueToCheckSignature, signature, "SHA256withRSA");

        if (isSignatureCorrect) {
            String pass = decryptToString(encryptedPass);
            return "First 4 and last 4 numbers of card: " + values[0] + "\n" +
                    "Time of operation: " + values[1] + "\n" +
                    "Amount: " + values[2] + "\n" +
                    "Type of operation: " + values[3] + "\n" +
                    "One time password: " + pass;
        }
        return "Error";
    }
}
