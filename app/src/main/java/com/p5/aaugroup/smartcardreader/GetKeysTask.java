package com.p5.aaugroup.smartcardreader;

import android.app.ProgressDialog;
import android.content.Context;
import android.os.AsyncTask;

import java.util.ArrayList;


/**
 * AsyncTask used when retriving the list of the locks keys from the database
 */
public class GetKeysTask extends AsyncTask<Void, Void, ArrayList<Key>> {

    ProgressDialog progressDialog;
    private Context context;
    private DBHandler dbh = new DBHandler();
    KeyPairHolder keyPairHolder;
    ArrayList<Key> keys = new ArrayList<>();
    String lockID;


    GetKeysTask(Context context, String lockID){
        this.lockID = lockID;
    }

    @Override
    protected ArrayList<Key> doInBackground(Void... voids) {
        // ArrayList<String> result = new ArrayList<>();

        synchronized (this) {
            try {
                dbh.getKeys(lockID);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return keys;
    }

    protected void onPostExecute( ArrayList<String> result) {
        //onPostExecute .. try to fill the drop down

    }
}
