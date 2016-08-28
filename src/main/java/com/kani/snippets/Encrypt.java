package com.kani.snippets;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Encoder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 * Created by kanishka on 8/28/16.
 */
public class Encrypt extends CertCommons {

    public static byte[] encrypt(String inputFile) throws KeyStoreException, IOException, CertificateEncodingException, CMSException {
        Security.addProvider(new BouncyCastleProvider());

        String KEYSTORE_ALIAS = "imago";
        byte[] inputFileBytes = FileUtils.readFileToByteArray(new File(inputFile));

        //retrieve certificate
        Certificate cert = getCertificate(KEYSTORE_ALIAS);
        X509Certificate x509Certificate = (X509Certificate) cert;

        CMSTypedData msg = new CMSProcessableByteArray(inputFileBytes);

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(x509Certificate).setProvider("BC"));

        CMSEnvelopedData encryptedData = edGen.generate(msg,
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider("BC").build());

        BASE64Encoder encoder = new BASE64Encoder();

        String envelopedData = encoder.encode(encryptedData.getEncoded());
        System.out.println("Encrypted Enveloped data: " + envelopedData);
        return encryptedData.getEncoded();
    }

    public static void decrypt(byte[] cipher) throws CMSException, IOException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        String KEYSTORE_ALIAS = "imago";
        Security.addProvider(new BouncyCastleProvider());

//        CMSEnvelopedDataParser envelopedDataParser = new CMSEnvelopedDataParser(new ByteArrayInputStream(cipher));
        PrivateKey privateKey = getPrivateKey(KEYSTORE_ALIAS);
//        Certificate cert = getCertificate(KEYSTORE_ALIAS);

        CMSEnvelopedData enveloped = new CMSEnvelopedData(cipher);
        Collection recip = enveloped.getRecipientInfos().getRecipients();

        KeyTransRecipientInformation rinfo = (KeyTransRecipientInformation) recip.iterator().next();
        byte[] content = rinfo.getContent(new JceKeyTransEnvelopedRecipient(privateKey).setProvider("BC"));

        System.out.println("Decrypted data");
        System.out.println(new String(content));
    }
}
