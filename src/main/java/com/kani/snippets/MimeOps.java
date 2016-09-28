package com.kani.snippets;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEKAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mail.smime.SMIMESignedParser;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import javax.activation.DataHandler;
import javax.activation.MimeType;
import javax.activation.MimeTypeParseException;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.ContentType;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

/**
 * Created by kanishka on 9/7/16.
 */
public class MimeOps extends CertCommons {

    public static MimeMessage createMimeMessage(MimeMultipart signedMimeMultipart) throws MessagingException, IOException {
        //        //create mime message
        Properties props = System.getProperties();
        Session session = Session.getDefaultInstance(props, null);

        MimeMessage mimeMessage = new MimeMessage(session);
        mimeMessage.setContent(signedMimeMultipart, signedMimeMultipart.getContentType());
        mimeMessage.saveChanges();

        //print mime message
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        mimeMessage.writeTo(byteArrayOutputStream);

        byte[] output = byteArrayOutputStream.toByteArray();
        System.out.println("---------------------------------------");
        System.out.println(new String(output));
        return mimeMessage;
    }

    public static MimeBodyPart createMimebodyPart(MimeMultipart signedMimeMultipart) throws MessagingException {
        MimeBodyPart tmpBody = new MimeBodyPart();
        tmpBody.setContent(signedMimeMultipart);
        tmpBody.setHeader("Content-Type", signedMimeMultipart.getContentType());
        return tmpBody;
    }

    public static MimeMultipart signMime(String inputFile) throws IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, MimeTypeParseException, MessagingException, OperatorCreationException, CertificateEncodingException, SMIMEException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String KEYSTORE_ALIAS = "imago";
        byte[] attachment = FileUtils.readFileToByteArray(new File(inputFile));

        //retrieve certificates
        Certificate cert = getCertificate(KEYSTORE_ALIAS);
        PrivateKey privKey = getPrivateKey(KEYSTORE_ALIAS);
        X509Certificate ourCert = (X509Certificate) cert;

        //create mime bodypart
        MimeBodyPart mimeBodyPart = new MimeBodyPart();
        MimeType mimeType = new MimeType("application/xml");

        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(attachment);
        ByteArrayDataSource byteArrayDataSource = new ByteArrayDataSource(byteArrayInputStream, mimeType.toString());
        DataHandler dh = new DataHandler(byteArrayDataSource);
        mimeBodyPart.setDataHandler(dh);

        mimeBodyPart.setHeader("Content-Type", mimeType.toString());
        mimeBodyPart.setHeader("Content-Transfer-Encoding", "binary"); //"BASE64" / "QUOTED-PRINTABLE" / "8BIT"   / "7BIT" / "BINARY" / x-token

        //sign preperations
        ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
        SMIMESignedGenerator smimeSignedGenerator = new SMIMESignedGenerator("binary");
        smimeSignedGenerator.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").build("SHA1withRSA", privKey, ourCert));

        List certList = new ArrayList();
        certList.add(ourCert);
        Store certs = new JcaCertStore(certList);

        smimeSignedGenerator.addCertificates(certs);


        //sign body part
        MimeMultipart signedMimeMultipart = smimeSignedGenerator.generate(mimeBodyPart);

        return signedMimeMultipart;
    }

    public static void validate(MimeMessage mimeMessage) throws IOException, MessagingException, OperatorCreationException, CMSException, CertificateException {
        SMIMESignedParser smimeSignedParser = new SMIMESignedParser(new JcaDigestCalculatorProviderBuilder().build(), (MimeMultipart) mimeMessage.getContent(), "binary");
        Store certs = smimeSignedParser.getCertificates();
        SignerInformationStore signerInfos = smimeSignedParser.getSignerInfos();

        Collection signers = signerInfos.getSigners();
        Iterator signersIterator = signers.iterator();

        if (signersIterator.hasNext()) {
            SignerInformation signer = (SignerInformation) signersIterator.next();
            Collection certCollection = certs.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
            X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider()).build(cert))) {
                System.out.println("Verified!");
            }
        }
    }

    public static MimeBodyPart encrypt(MimeBodyPart part) throws NoSuchAlgorithmException, CertificateEncodingException, CMSException, SMIMEException, KeyStoreException {
        String KEYSTORE_ALIAS = "imago";

        Certificate cert = getCertificate(KEYSTORE_ALIAS);
        X509Certificate x509Cert = (X509Certificate) cert;

        SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();
        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(x509Cert).setProvider("BC"));

        MimeBodyPart encData = gen.generate(part, new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).build());

        System.gc();

        return encData;
    }

    public static MimeBodyPart decrypt(MimeBodyPart part) throws MessagingException, CMSException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, SMIMEException {
        String KEYSTORE_ALIAS = "imago";

        if (!isEncrypted(part)) {
            throw new IllegalStateException("Content-Type indicates data isn't encrypted");
        }

        Certificate cert = getCertificate(KEYSTORE_ALIAS);
        PrivateKey privKey = getPrivateKey(KEYSTORE_ALIAS);
        X509Certificate x509Cert = (X509Certificate) cert;

        SMIMEEnveloped envelope = new SMIMEEnveloped(part);

        RecipientId recId = new KeyTransRecipientId(toX500Name(x509Cert.getIssuerX500Principal()), x509Cert.getSerialNumber());

        RecipientInformation recipientInfo = envelope.getRecipientInfos().get(recId);

        Recipient recipient = new JceKeyTransEnvelopedRecipient(getPrivateKey(KEYSTORE_ALIAS));

        byte[] decryptedData = recipientInfo.getContent(recipient);

        return SMIMEUtil.toMimeBodyPart(decryptedData);
    }

    public static boolean isEncrypted(MimeBodyPart part) throws MessagingException {
        ContentType contentType = new ContentType(part.getContentType());
        String baseType = contentType.getBaseType().toLowerCase();

        if (baseType.equalsIgnoreCase("application/pkcs7-mime")) {
            String smimeType = contentType.getParameter("smime-type");

            return ((smimeType != null) && smimeType.equalsIgnoreCase("enveloped-data"));
        }

        return false;
    }

    public static X500Name toX500Name(X500Principal principal) {
        byte[] bytes = principal.getEncoded();
        return X500Name.getInstance(bytes);
    }


}
