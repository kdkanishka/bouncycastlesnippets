package com.kani.snippets;


import org.apache.commons.io.FileUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import sun.misc.BASE64Encoder;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * Created by kanishka on 8/28/16.
 */
public class CMSSign extends CertCommons {
    public static String sign(String inputFile, String signedFile) throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, UnrecoverableKeyException, CMSException, InvalidKeyException, SignatureException, CertificateEncodingException, OperatorCreationException {
        String KEYSTORE_ALIAS = "imago";
        byte[] inputFileBytes = FileUtils.readFileToByteArray(new File(inputFile));

        //retrieve certificate
        Certificate cert = getCertificate(KEYSTORE_ALIAS);

        //sign
        PrivateKey privKey = getPrivateKey(KEYSTORE_ALIAS);
        Signature signature = Signature.getInstance("SHA1WithRSA", "BC");
        signature.initSign(privKey);
        signature.update(inputFileBytes);

        //build cms
        X509Certificate x509Certificate = (X509Certificate) cert;
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray(signature.sign());
        certList.add(x509Certificate);
        Store certs = new JcaCertStore(certList);

        //build cms generator
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privKey);
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha1Signer, x509Certificate));
        gen.addCertificates(certs);
        CMSSignedData sigData = gen.generate(msg, true); //signed data is encapsulated in the signature

        BASE64Encoder encoder = new BASE64Encoder();

        String signedContent = encoder.encode((byte[]) sigData.getSignedContent().getContent());
        System.out.println("Signed content: " + signedContent + "\n");

        String envelopedData = encoder.encode(sigData.getEncoded());
        System.out.println("Signed Enveloped data: " + envelopedData);

        return envelopedData;
    }

    public static void verify(String envelopedData) throws CMSException, CertificateException, OperatorCreationException {
        Security.addProvider(new BouncyCastleProvider());

        CMSSignedData cms = new CMSSignedData(Base64.decode(envelopedData.getBytes()));
        Store store = cms.getCertificates();
        SignerInformationStore signers = cms.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();
        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            Collection certCollection = store.getMatches(signer.getSID());
            Iterator certIt = certCollection.iterator();
            X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
            X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
                System.out.println("verified");
            }
        }
    }

}
