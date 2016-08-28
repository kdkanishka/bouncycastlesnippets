package com.kani.snippets;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Security;

/**
 * Created by kanishka on 8/26/16.
 */
public class KeystoreLoader {

    public static KeyStore load(String path,String pass) {
        KeyStore ks = null;
        char[] password = null;

        Security.addProvider(new BouncyCastleProvider());

        try {
            ks = KeyStore.getInstance("PKCS12");
            password = pass.toCharArray();
            ks.load(new FileInputStream(path), password);

            System.out.println("Keystore loaded successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ks;
    }
}
