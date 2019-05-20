package hfu.pki.utils;

import hfu.pki.base.Main;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;

public class Utils {

    public static final String DEFAULT_KEYPAIR_ALGORITHM = "RSA";

    public static KeyPair createKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(DEFAULT_KEYPAIR_ALGORITHM, "BC");
        keyPairGenerator.initialize(1024, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static void storeCertificateAsPEM(X509Certificate certificate) throws IOException, CertificateEncodingException {
        String fileName = certificate.getSerialNumber() + ".pem";
        storeCertificateAsPEM(certificate, fileName);
    }

    public static void storeCertificateAsPEM(X509Certificate certificate, String fileName) throws CertificateEncodingException, IOException {
        PemWriter writer = new PemWriter(new FileWriter(fileName));
        writer.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
        writer.flush();
        writer.close();
    }

    public static void storeCRLAsPEM(X509CRL crl) throws IOException, CRLException {
        storeCRLAsPEM(crl, Configurations.VA_CRL_FILENAME);
    }

    public static void storeCRLAsPEM(X509CRL crl, String fileName) throws IOException, CRLException {
        PemWriter writer = new PemWriter(new FileWriter(fileName));
        writer.writeObject(new PemObject("CRL", crl.getEncoded()));
        writer.flush();
        writer.close();
    }

    public static X509Certificate loadCertificateFromPEM(String fileName) throws IOException, CertificateException {
        InputStream certificateFile = Utils.getInputStreamFromResources(fileName);
        PemReader reader = new PemReader(new InputStreamReader(certificateFile));
        byte[] requestBytes = reader.readPemObject().getContent();
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream in = new ByteArrayInputStream(requestBytes);
        return (X509Certificate) factory.generateCertificate(in);
    }

    public static void storeKeyPair(KeyPair keyPair, String path) throws IOException {
        String privateKeyFileName = "ca_private.key";
        String publicKeyFileName = "ca_public.key";
        storeKeyPair(keyPair, path, privateKeyFileName, publicKeyFileName);
    }

    /* https://snipplr.com/view/18368/ */
    public static void storeKeyPair(KeyPair keyPair, String path, String privateKeyFileName, String publicKeyFileName) throws IOException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Store Public Key.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(path + "/" + publicKeyFileName);
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        fos = new FileOutputStream(path + "/" + privateKeyFileName);
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();
    }

    public static KeyPair loadKeyPair() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        String privateKeyFileName = "ca_private.key";
        String publicKeyFileName = "ca_public.key";
        return loadKeyPair(privateKeyFileName, publicKeyFileName);
    }

    /* https://snipplr.com/view/18368/ */
    public static KeyPair loadKeyPair(String privateKeyFileName, String publicKeyFileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Read Public Key.
        InputStream filePublicKey = getInputStreamFromResources(publicKeyFileName);
        byte[] encodedPublicKey = filePublicKey.readAllBytes();
        filePublicKey.close();

        // Read Private Key.
        InputStream filePrivateKey = getInputStreamFromResources(privateKeyFileName);
        byte[] encodedPrivateKey = filePrivateKey.readAllBytes();
        filePrivateKey.close();

        // Generate KeyPair.
        KeyFactory keyFactory = KeyFactory.getInstance(DEFAULT_KEYPAIR_ALGORITHM);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        return new KeyPair(publicKey, privateKey);
    }

    public static X509CRL loadCRLFromPEM(String fileName) throws IOException, CRLException, CertificateException {
        InputStream crlFile = Utils.getInputStreamFromResources(fileName);
        PemReader reader = new PemReader(new InputStreamReader(crlFile));
        byte[] requestBytes = reader.readPemObject().getContent();
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream in = new ByteArrayInputStream(requestBytes);
        return (X509CRL) factory.generateCRL(in);
    }

    public static PKCS10CertificationRequest createCSR(String subject, KeyPair requestKeyPair) throws OperatorCreationException {
        X500Principal entitySubject = new X500Principal(subject);
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(entitySubject, requestKeyPair.getPublic());

        // Sign the request
        JcaContentSignerBuilder csrSignerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
        ContentSigner csrSigner = csrSignerBuilder.build(requestKeyPair.getPrivate());
        return csrBuilder.build(csrSigner);
    }

    public static X509Certificate createSelfSignedCertificate(KeyPair keyPair, String subjectDN) throws OperatorCreationException, CertificateException {
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        X500Name dnName = new X500Name(subjectDN);

        // Using the current timestamp as the certificate serial number
        BigInteger certSerialNumber = new BigInteger(Long.toString(now));
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        // Use appropriate signature algorithm based on your keyPair algorithm.
        String signatureAlgorithm = "SHA256WithRSA";
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, subjectPublicKeyInfo);
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(bcProvider).build(keyPair.getPrivate());
        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().getCertificate(certificateHolder);
    }

    public static InputStream getInputStreamFromResources(String fileName) {
        ClassLoader classLoader = Main.class.getClassLoader();
        InputStream resource = classLoader.getResourceAsStream(fileName);
        if (resource == null) {
            throw new IllegalArgumentException("file is not found!");
        } else {
            return resource;
        }

    }
}
