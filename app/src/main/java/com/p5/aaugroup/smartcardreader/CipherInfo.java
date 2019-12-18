package com.p5.aaugroup.smartcardreader;

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;


/**
 * Contains encryption data.
 */
public class CipherInfo {

    private SecretKey secretKey;
    private byte[] bytes;
    private byte[] iv;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public CipherInfo(byte[] bytes){
        this.bytes = bytes;
    }

    public SecretKey getSecretKey(){
        return secretKey;
    }
    public byte[] getBytes(){
        return bytes;
    }
    public byte[] getIv(){
        return iv;
    }
    public PrivateKey getPrivateKey() {
        return privateKey;
    }
    public PublicKey getPublicKey() {
        return publicKey;
    }
    public void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }
    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }
    public void setIv(byte[] iv) {
        this.iv = iv;
    }
}
