package hfu.pki.utils;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.security.auth.x500.X500Principal;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class Utils {

    public static KeyPair createKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(1024, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static void storeCertificateAsPEM(X509Certificate certificate) throws CertificateEncodingException, IOException {
        String fileName = certificate.getSerialNumber() + ".pem";
        PemWriter writer = new PemWriter(new FileWriter(fileName));
        writer.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
        writer.flush();
        writer.close();
    }

    public static PKCS10CertificationRequest createCSR(String subject, KeyPair requestKeyPair) throws OperatorCreationException {
        X500Principal entitySubject = new X500Principal(subject);
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(entitySubject, requestKeyPair.getPublic());

        // Sign the request
        JcaContentSignerBuilder csrSignerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
        ContentSigner csrSigner = csrSignerBuilder.build(requestKeyPair.getPrivate());
        return csrBuilder.build(csrSigner);
    }
}
