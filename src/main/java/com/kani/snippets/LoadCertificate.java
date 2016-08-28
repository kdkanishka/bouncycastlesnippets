package com.kani.snippets;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by kanishka on 8/28/16.
 */
public class LoadCertificate {

    public static X509Certificate loadX509Certificate(String certPath) {
        X509Certificate cert = null;
        try {
            //load DER certificate
            InputStream inStream = new FileInputStream(certPath);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(inStream);
            inStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cert;
    }
}
