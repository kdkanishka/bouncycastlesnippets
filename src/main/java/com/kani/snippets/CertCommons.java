package com.kani.snippets;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;

/**
 * Created by kanishka on 8/28/16.
 */
public class CertCommons {

    static Certificate getCertificate(String alias) throws KeyStoreException {
        KeyStore ks = getKeyStore();
        Certificate cert = ks.getCertificate(alias);
        return cert;
    }

     static PrivateKey getPrivateKey(String alias) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        String password = "Wiiagdfsa";
        KeyStore ks = getKeyStore();
        PrivateKey privKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
        return privKey;
    }

     static KeyStore getKeyStore() {
        String password = "Wiiagdfsa";
        KeyStore ks = KeystoreLoader.load("/home/kanishka/Desktop/testkeys/certs.p12", password);
        return ks;
    }
}
