package com.p5.aaugroup.smartcardreader;


import java.security.PrivateKey;
import java.security.PublicKey;


/**
 * used to store the locks RSA keys
 */
public class KeyPairHolder {

    PublicKey publicKey;
    PrivateKey privateKey;

    public KeyPairHolder(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
}
