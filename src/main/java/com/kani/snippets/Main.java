package com.kani.snippets;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

/**
 * Created by kanishka on 8/26/16.
 * more info on http://nyal.developpez.com/tutoriel/java/bouncycastle/
 */
public class Main {
    public static void main(String[] args) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, InvalidAlgorithmParameterException, NoSuchProviderException, IOException, OperatorCreationException, SignatureException, CMSException, InvalidKeyException {

        //snippet 1 (load certificates from a P12 keystore)
        String password = "Wiiagdfsa";
        KeyStore ks = KeystoreLoader.load("/home/kanishka/Desktop/testkeys/certs.p12", password);

        Enumeration<String> aliases = ks.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println(alias);

            PrivateKey privKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
            Certificate cert = ks.getCertificate(alias);
            PublicKey publicKey = ks.getCertificate(alias).getPublicKey();
        }

        //snippet 2 (Load x509 certificate)
//        X509Certificate cert = LoadCertificate.loadX509Certificate("/home/kanishka/Desktop/testkeys/certificate.cer");
//        System.out.println(cert);

        //snipper 3 (sign and verify)
//        String envelopedData = CMSSign.sign("/home/kanishka/Desktop/testkeys/doc_to_sign","");
//        CMSSign.verify(envelopedData);

        //snippet 4 (encrypt/decrypt)
        byte[] encrypted = Encrypt.encrypt("/home/kanishka/Desktop/testkeys/doc_to_sign");
        Encrypt.decrypt(encrypted);

    }
}
