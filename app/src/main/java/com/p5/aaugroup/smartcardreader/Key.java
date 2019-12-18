package com.p5.aaugroup.smartcardreader;

import com.google.firebase.Timestamp;

import java.security.PublicKey;

/**
 * used to store the data about the keys
 */

public class Key {

    String userName;
    String keyID;
    String keyHash;
    Integer accessLevel;
    Timestamp expirationDate;
    PublicKey publicKey;

    public Key(String userName, String keyID, String keyHash, Integer accessLevel, Timestamp expirationDate,PublicKey publicKey) {
        this.userName = userName;
        this.keyID = keyID;
        this.keyHash = keyHash;
        this.accessLevel = accessLevel;
        this.expirationDate = expirationDate;
        this.publicKey = publicKey;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getKeyID() {
        return keyID;
    }

    public void setKeyID(String keyID) {
        this.keyID = keyID;
    }

    public String getKeyHash() {
        return keyHash;
    }

    public void setKeyHash(String keyHash) {
        this.keyHash = keyHash;
    }

    public Integer getAccessLevel() {
        return accessLevel;
    }

    public void setAccessLevel(Integer accessLevel) {
        this.accessLevel = accessLevel;
    }

    public Timestamp getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(Timestamp expirationDate) {
        this.expirationDate = expirationDate;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }
}
