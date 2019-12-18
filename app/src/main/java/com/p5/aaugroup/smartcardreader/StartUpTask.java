package com.p5.aaugroup.smartcardreader;

import android.app.ProgressDialog;
import android.content.Context;
import android.os.AsyncTask;

import java.util.ArrayList;


/**
 * AsyncTask used when retriving the locks RSA keys from the database
 */
public class StartUpTask extends AsyncTask<Void, Void, ArrayList<Key>> {

    ProgressDialog progressDialog;
    private Context context;
    private DBHandler dbh = new DBHandler();
    KeyPairHolder keyPairHolder;
    ArrayList<Key> keys = new ArrayList<>();
    String lockID;


    StartUpTask(Context context, String lockID){
        this.lockID = lockID;
    }

    @Override
    protected ArrayList<Key> doInBackground(Void... voids) {
        // ArrayList<String> result = new ArrayList<>();

        synchronized (this) {
            try {
                keyPairHolder = dbh.startLock(lockID);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return keys;
    }

    protected void onPostExecute( ArrayList<String> result) {
        //onPostExecute .. try to fill the drop down
        //MainActivity.keyPairHolder = keyPairHolder;
    }
}
