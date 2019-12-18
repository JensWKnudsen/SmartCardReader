package com.p5.aaugroup.smartcardreader

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_main.*
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.util.*

/**
 * Main activity used to run NFC communication
 */
class MainActivity : AppCompatActivity(), NfcAdapter.ReaderCallback {

    private var nfcAdapter: NfcAdapter? = null
    var keys: ArrayList<Key>? = null
    var keyPairHolder: KeyPairHolder? = null
    var dBHandler: DBHandler? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val encryptionHandler: EncryptionHandler = object : EncryptionHandler(){}
        dBHandler = object : DBHandler(){}

        var startUpTask: StartUpTask = StartUpTask(this,"G4dNJP0cipi1OLMFF5Y3")
        startUpTask.execute()

        var getKeysTask: GetKeysTask = GetKeysTask(this,"G4dNJP0cipi1OLMFF5Y3")
        getKeysTask.execute()
        //(dBHandler as DBHandler).setKeys("ySlYpqaAhmzFKiN0XjS4")

        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
    }

    public override fun onResume() {
        super.onResume()
        nfcAdapter?.enableReaderMode(this, this,
                NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
                null)
    }

    public override fun onPause() {
        super.onPause()
        nfcAdapter?.disableReaderMode(this)
    }

    override fun onTagDiscovered(tag: Tag?) {


        Log.e("Startup","tag found")
        keyPairHolder = dBHandler!!.keyPairHolder
        keys = dBHandler!!.keyArrayList
        Log.e("Startup","list of keys: " + keys?.size)
        val byteArray = keyPairHolder?.getPublicKey()?.encoded
        val charset = Charsets.UTF_8
        var stage = "0".toByteArray(charset)
        val encryptionHandler: EncryptionHandler = object : EncryptionHandler(){}
        var publicKeyMatch = false


        val isoDep = IsoDep.get(tag)
        isoDep.connect()
        val prefix = "00A4040007";
        if(isoDep.isConnected){
            Log.e("isoDep","is connected" + tag)

            isoDep.setTimeout(5000)
            Log.e("encryption","full message sent: "
                    + prefix + "A0000002471001" + stage + byteArray!!)
            Log.e("tag","tage is :" + isoDep.isConnected)
            val response = isoDep.transceive(Utils.hexStringToByteArray
            (prefix + "A0000002471001")+ stage+ byteArray)

            val KeyFac = KeyFactory.getInstance("RSA")
            val x509KeySpec = X509EncodedKeySpec(response)
            var asymmetricPubKeyApp = KeyFac.generatePublic(x509KeySpec)

            // ForEach
            keys?.forEach {
                Log.e("Key in list",dBHandler?.encodeHexString(it.publicKey.encoded))
                Log.e("Key recived",dBHandler?.encodeHexString(asymmetricPubKeyApp.encoded))
                if(Arrays.equals(it.publicKey.encoded, asymmetricPubKeyApp.encoded )){
                    publicKeyMatch = true
                }
            }
            if(publicKeyMatch){
                stage = "1".toByteArray(charset)
                Log.e("encryption","Message sent: " + stage.toString())
                var encryptedPublicDHkeyOfPi = encryptionHandler.Stage2(asymmetricPubKeyApp)
                Log.e("encryption","Message sent: " + dBHandler?.encodeHexString(encryptedPublicDHkeyOfPi))
                val response2 = isoDep.transceive(Utils.hexStringToByteArray(prefix + "A0000002471001")+ stage + encryptedPublicDHkeyOfPi)


                var requestForKey = encryptionHandler.stage3(response2,keyPairHolder?.getPrivateKey())
                var doorKeyMessage = isoDep.transceive(Utils.hexStringToByteArray(prefix + "A0000002471001")+ stage + requestForKey)

                var doorKey = encryptionHandler.readDoorKey(doorKeyMessage)

                var responseString = String(doorKey);

                var doorKeyMatch = false
                keys?.forEach {
                    if(it.keyHash.equals(responseString)){
                        doorKeyMatch = true
                    }
                }
                if (doorKeyMatch){

                    responseString = String(doorKey);
                    runOnUiThread { textView.append("\nCard Response: "
                            + responseString) }

                }else{
                    Log.e("Key check","Door keys don't match")
                }


                /*
                var responseInString = ""
                for (byt in response){

                    responseInString = responseInString + byt.toString()

                }
                */

            }else{
                Log.e("Key check","Public keys don't match")
            }

        }else{
            Log.e("isoDep","is not connected")
        }

        isoDep.close()


    }

    companion object {
        lateinit var keyPairHolder: KeyPairHolder
    }




}
