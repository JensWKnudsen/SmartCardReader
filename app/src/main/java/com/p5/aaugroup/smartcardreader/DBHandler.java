package com.p5.aaugroup.smartcardreader;

import android.util.Log;

import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.Timestamp;
import com.google.firebase.firestore.DocumentReference;
import com.google.firebase.firestore.DocumentSnapshot;
import com.google.firebase.firestore.FirebaseFirestore;
import com.google.firebase.firestore.Query;
import com.google.firebase.firestore.QueryDocumentSnapshot;
import com.google.firebase.firestore.QuerySnapshot;
import com.google.firebase.firestore.SetOptions;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;

import androidx.annotation.NonNull;

/**
 * DataBaseHandler handles all communication with the database
 * Final strings are used as references to database collections and fields
 * The information about the lock is stored here
 */

public class DBHandler {

    private FirebaseFirestore db = FirebaseFirestore.getInstance();
    private static final String LOCKS_COLLECTION = "Locks";
    private static final String USERSOFLOCKS_COLLECTION = "UsersOfLock";
    private static final String ACCESSLEVEL = "Access Level";
    private static final String KEY = "Key";
    private static final String USERID = "UserID";
    private static final String USERNAME = "Username";
    private static final String EXPIRATION = "Expiration";
    private static final String USERPUBLICKEY = "UserPublicKey";
    private static final String PUBLICKEY = "PublicKey";
    private static final String PRIVATEKEY = "PrivateKey";

    private static ArrayBlockingQueue<ArrayList<Key>> ArrayKeysBlockingQueue = new ArrayBlockingQueue<>(1);
    private static ArrayBlockingQueue<ArrayList<String>> ArrayStringBlockingQueue = new ArrayBlockingQueue<>(1);


    static KeyPairHolder keyPairHolder;
    static ArrayList<Key> keyArrayList;

    public KeyPairHolder getKeyPairHolder() {
        return keyPairHolder;
    }

    public void setKeyPairHolder(KeyPairHolder keyPairHolder) {
        this.keyPairHolder = keyPairHolder;
    }

    public ArrayList<Key> getKeyArrayList() {
        Log.e("Getter","size of array list is: " + keyArrayList.size());
        return keyArrayList;
    }

    public void setKeyArrayList(ArrayList<Key> keyArrayList) {
        this.keyArrayList = keyArrayList;
    }

    public KeyPairHolder startLock(String lockID){
        ArrayStringBlockingQueue.clear();
        DocumentReference KeysOfLock = db.collection(LOCKS_COLLECTION).document(lockID);
        KeysOfLock.get().addOnCompleteListener(new OnCompleteListener<DocumentSnapshot>() {
            @Override
            public void onComplete(@NonNull Task<DocumentSnapshot> task) {
                if (task.isSuccessful()) {
                    DocumentSnapshot document = task.getResult();
                    if (document.exists()) {
                        ArrayList<String> keys = new ArrayList<>();
                        keys.add(document.getString(PUBLICKEY));
                        keys.add(document.getString(PRIVATEKEY));
                        try {
                            ArrayStringBlockingQueue.put(keys);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    } else {
                    }
                } else {
                }
            }
        });
        ArrayList<String> keys = null;
        try {
            keys = ArrayStringBlockingQueue.take();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        try {
            Log.e("convert keys","starting key conversion");

            byte[] decodedPublicKey = decodeHexString(keys.get(0));
            KeyFactory KeyFac = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(decodedPublicKey);
            PublicKey AsymmetricPubKey = KeyFac.generatePublic(x509KeySpec);

            byte[] decodedPrivateKey = decodeHexString(keys.get(1));
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(decodedPrivateKey);
            PrivateKey AsymmetricPrivateKey = KeyFac.generatePrivate(pkcs8EncodedKeySpec);

            KeyPairHolder keyPairHolder = new KeyPairHolder(AsymmetricPubKey,AsymmetricPrivateKey);

            this.keyPairHolder = keyPairHolder;
            return keyPairHolder;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return keyPairHolder;

    }



    public void getKeys(String lockID){
        ArrayKeysBlockingQueue.clear();
        Query KeysOfLock = db.collection(LOCKS_COLLECTION).document(lockID).collection(USERSOFLOCKS_COLLECTION);
        ArrayList<Key> listOfKeys = new ArrayList<>();
        KeysOfLock.get().addOnCompleteListener(new OnCompleteListener<QuerySnapshot>() {
            @Override
            public void onComplete(@NonNull Task<QuerySnapshot> task) {
                if (task.isSuccessful()) {
                    ArrayList<Key> listOfKeys = new ArrayList<>();
                    for (QueryDocumentSnapshot document : task.getResult()) {


                        String name = document.getString(USERNAME);
                        String id = document.getId();
                        String hash = document.getString(KEY);
                        Integer accessLevel = document.getLong(ACCESSLEVEL).intValue();
                        Timestamp timestamp = document.getTimestamp(EXPIRATION);

                        String stringPublicKey = document.getString(USERPUBLICKEY);
                        KeyFactory KeyFac = null;
                        PublicKey AsymmetricPubKey = null;
                        try {
                            byte[] publicKeyBytes = decodeHexString(stringPublicKey);
                            KeyFac = KeyFactory.getInstance("RSA");
                            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
                            AsymmetricPubKey = KeyFac.generatePublic(x509KeySpec);
                        } catch (NoSuchAlgorithmException e) {
                            e.printStackTrace();
                        } catch (InvalidKeySpecException e) {
                            e.printStackTrace();
                        }

                        Key key = new Key(name,id,hash,accessLevel,timestamp,AsymmetricPubKey);
                        listOfKeys.add(key);

                    }
                    try {
                        ArrayKeysBlockingQueue.put(listOfKeys);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                } else {
                    Log.w("getKeys", "Error getting documents.", task.getException());
                }
            }
        });

        try {
            listOfKeys = ArrayKeysBlockingQueue.take();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        Log.e("Database","List of keys is: " + listOfKeys.size());

        keyArrayList = listOfKeys;

    }

    public void setKeys(String ID) throws NoSuchAlgorithmException {
        Log.e("Add key","key added");
        Map<String, Object> lockData = new HashMap<>();
        EncryptionHandler encryptionHandler = new EncryptionHandler();
        KeyPair keyPair = encryptionHandler.asymmetricKeyGeneration();


        String publicKey = encodeHexString(keyPair.getPublic().getEncoded());
        //= new String(keyPair.getPublic().getEncoded());
        Log.e("Add key","publickey added: " + publicKey);

        lockData.put("PublicKey",publicKey );
        String privateKey = encodeHexString(keyPair.getPrivate().getEncoded());
        //new String(keyPair.getPrivate().getEncoded());
        Log.e("Add key","privatekey added: " + privateKey);
        lockData.put("PrivateKey",privateKey);
        db.collection("Users").document(ID).set(lockData, SetOptions.merge());

    }

    public String encodeHexString(byte[] byteArray) {
        StringBuffer hexStringBuffer = new StringBuffer();
        for (int i = 0; i < byteArray.length; i++) {
            hexStringBuffer.append(byteToHex(byteArray[i]));
        }
        return hexStringBuffer.toString();
    }


    public byte[] decodeHexString(String hexString) {
        if (hexString.length() % 2 == 1) {
            throw new IllegalArgumentException(
                    "Invalid hexadecimal String supplied.");
        }

        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
        }
        return bytes;
    }


    public byte hexToByte(String hexString) {
        int firstDigit = toDigit(hexString.charAt(0));
        int secondDigit = toDigit(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }

    private int toDigit(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if(digit == -1) {
            throw new IllegalArgumentException(
                    "Invalid Hexadecimal Character: "+ hexChar);
        }
        return digit;
    }

    public String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }

}
