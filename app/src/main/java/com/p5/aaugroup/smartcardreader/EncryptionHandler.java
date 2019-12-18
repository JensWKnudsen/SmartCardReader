package com.p5.aaugroup.smartcardreader;

import android.util.Log;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * EncryptionHandler generates RSA and AES keys
 * Also used to encrypt and decrypt messages with RSA or AES encryption.
 */
public class EncryptionHandler {

    KeyAgreement piKeyAgree;
    SecretKeySpec piAesKeySpec;

    public KeyPair asymmetricKeyGeneration() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public byte[] Stage2(PublicKey asymmetricPublicKeyApp) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        KeyPair PiDHKpair = createDHKeypair();
        piKeyAgree = DHKeyAgreement(PiDHKpair);
        byte[] piDHPubKeyEnc = PiDHKpair.getPublic().getEncoded();

        byte[] encryptedDHPublicKeyOfPi = asymmetricEncrypt(piDHPubKeyEnc,asymmetricPublicKeyApp).getBytes();
        return encryptedDHPublicKeyOfPi;

    }

    public byte[] stage3(byte[] message, PrivateKey asymmetricPrivateKeyPi) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {

        byte[] AppDHPubKeyEnc = asymmetricDecrypt(message,asymmetricPrivateKeyPi);

        KeyFactory piKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(AppDHPubKeyEnc);
        PublicKey AppDHPubKey = piKeyFac.generatePublic(x509KeySpec);
        piKeyAgree.doPhase(AppDHPubKey, true);

        byte[] piSharedSecret = piKeyAgree.generateSecret();
        piAesKeySpec = new SecretKeySpec(piSharedSecret, 0, 16, "AES");

        byte[] requestMessage = "request for key".getBytes();

        CipherInfo requestMessageCipherInfo = symmetricEncrypt(requestMessage,piAesKeySpec);

        int lengthOfIV = requestMessageCipherInfo.getIv().length;

        byte[] lengthOfIVInBytes = ByteBuffer.allocate(8).putInt(lengthOfIV).array();

        byte[] messageToApp = new byte[8 + requestMessageCipherInfo.getIv().length + requestMessageCipherInfo.getBytes().length];

        System.arraycopy(lengthOfIVInBytes, 0, messageToApp, 0, 8);

        System.arraycopy(requestMessageCipherInfo.getIv(), 0, messageToApp, 8, requestMessageCipherInfo.getIv().length);

        System.arraycopy(requestMessageCipherInfo.getBytes(), 0, messageToApp, 8 + requestMessageCipherInfo.getIv().length, requestMessageCipherInfo.getBytes().length);

        return messageToApp;

    }

    public byte[] readDoorKey(byte[] doorKeyMessage) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        byte[] ivLength = Arrays.copyOfRange(doorKeyMessage,0,8);

        byte[] iv = Arrays.copyOfRange(doorKeyMessage,8, 8 + ByteBuffer.wrap(ivLength).getInt());

        byte[] message = Arrays.copyOfRange(doorKeyMessage,8 + ByteBuffer.wrap(ivLength).getInt() ,doorKeyMessage.length);

        byte[] decryptedMessage = symmetricDecrypt(message,iv,piAesKeySpec);

        return decryptedMessage;

    }



    public KeyPair createDHKeypair() throws NoSuchAlgorithmException {
        KeyPairGenerator PiKpairGen = KeyPairGenerator.getInstance("DH");
        PiKpairGen.initialize(512);
        return PiKpairGen.generateKeyPair();
    }

    // Pi creates and initializes its DH KeyAgreement object
    public KeyAgreement DHKeyAgreement(KeyPair PiDHKpair) throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement PiKeyAgree = KeyAgreement.getInstance("DH");
        PiKeyAgree.init(PiDHKpair.getPrivate());
        return PiKeyAgree;
    }

    public CipherInfo asymmetricEncrypt(byte[] inputText, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher;

        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); //ISO10126Padding //PKCS1Padding
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] ciphertext = cipher.doFinal(inputText);

        CipherInfo cipherInfo = new CipherInfo(ciphertext);
        cipherInfo.setPrivateKey(privateKey);

        return cipherInfo;
    }

    public CipherInfo asymmetricEncrypt(byte[] inputText, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher;

        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); //ISO10126Padding //PKCS1Padding
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        Log.d("encrypt", "test 1: " + Arrays.toString(inputText));
        byte[] ciphertext = cipher.doFinal(inputText);
        Log.d("encrypt", "test 2");
        CipherInfo cipherInfo = new CipherInfo(ciphertext);
        cipherInfo.setPublicKey(publicKey);

        return cipherInfo;
    }

    public byte[] asymmetricDecrypt(byte[] bytes, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher;
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); //ISO10126Padding

        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] plaintext = cipher.doFinal(bytes);

        return plaintext;
    }

    public CipherInfo symmetricEncrypt(byte[] inputText, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher;

        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING"); //ISO10126Padding
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] iv = cipher.getIV();

        Log.d("encrypt","Length of iv: " + String.valueOf(iv.length));
        Log.d("encrypt","iv: " + iv);


        byte[] ciphertext = cipher.doFinal(inputText);

        CipherInfo cipherInfo = new CipherInfo(ciphertext);
        cipherInfo.setSecretKey(secretKey);
        cipherInfo.setIv(iv);

        return cipherInfo;
    }

    public byte[] symmetricDecrypt(byte[] inputText, byte[] iv, SecretKey symmetricPhoneKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        Cipher cipher;
        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING"); //ISO10126Padding
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, symmetricPhoneKey, ivParameterSpec);

        byte[] plaintext = cipher.doFinal(inputText);

        return plaintext;
    }

}
