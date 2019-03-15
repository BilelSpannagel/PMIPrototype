package org.jscep;

import com.serialization.ObjectDeserializer;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jscep.client.Client;
import org.jscep.client.ClientException;
import org.jscep.client.DefaultCallbackHandler;
import org.jscep.client.verification.CertificateVerifier;
import org.jscep.client.verification.OptimisticCertificateVerifier;
import org.jscep.transaction.OperationFailureException;
import org.jscep.transaction.TransactionException;
import org.jscep.transport.response.Capabilities;
import org.junit.Test;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.*;

/**
 * Created by kevin on 16.05.2017.
 */
public class MyTests {

    @Test
    public void myTest() throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException, ClientException, TransactionException, CertStoreException {
        HttpClient client = new DefaultHttpClient();
        String serialNumber = "580b4336525d9ab722ff";
        String url = "http://localhost:8080/PMITest_war_exploded/pki/get/" + serialNumber;
        // System.out.println("Url: " + url);
        HttpGet get = new HttpGet(url);
        HttpResponse response = client.execute(get);
        X509Certificate certificateToCheck = convertToCertificate(response);
        System.out.println(certificateToCheck == null ? "No certificateToCheck found." : certificateToCheck);

        // System.out.println("Read CA cert store...");
        CertStore caCertStore = getCACertStore();
        // System.out.println("Finished...");
        Collection<? extends Certificate> certificates = caCertStore.getCertificates(null);

        System.out.println("Start validation...");
        X509CRL revocationList = getRevocationList(certificateToCheck);
        boolean revoked = revocationList.isRevoked(certificateToCheck);

        // Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // PKIXCertPathBuilderResult pkixCertPathBuilderResult = org.jscep.validation.CertificateVerifier.verifyCertificate(certificateToCheck, caCertificates);
        System.out.println("Finished validation...");
    }

    private static X509CRL getRevocationList(X509Certificate certificate) throws MalformedURLException, NoSuchAlgorithmException, CertificateException, OperatorCreationException, ClientException, OperationFailureException {
        URL url = new URL("http://141.28.105.137/scep/scep");
        CertificateVerifier verifier = new OptimisticCertificateVerifier();
        CallbackHandler handler = new DefaultCallbackHandler(verifier);

        Client client = new Client(url, handler);
        // Create a self signed certificate for communication
        KeyPair jscepKeyPair = createRandomKeyPair();
        X509Certificate ownCertificate = createOwnCertificate(jscepKeyPair, client);
        X509CRL crl = client.getRevocationList(ownCertificate, jscepKeyPair.getPrivate(), certificate.getIssuerX500Principal(), certificate.getSerialNumber());
        return crl;
    }

    private static CertStore getCACertStore() throws MalformedURLException, ClientException {
        URL url = new URL("http://141.28.105.137/scep/scep");
        CertificateVerifier verifier = new OptimisticCertificateVerifier(); // new ConsoleCertificateVerifier();
        CallbackHandler handler = new DefaultCallbackHandler(verifier);

        Client client = new Client(url, handler);
        CertStore caCertificate = client.getCaCertificate();
        System.out.println(caCertificate);
        return caCertificate;
    }

    private static X509Certificate convertToCertificate(HttpResponse response) {
        try {
            String content = convertStreamToString(response.getEntity().getContent());
            String serializedCertificate = content.replace("=", "");
            return ObjectDeserializer.fromString(serializedCertificate);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String convertStreamToString(java.io.InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }

    private static X509Certificate createOwnCertificate(KeyPair ownCertificateKeyPair, Client client) throws CertificateException, OperatorCreationException {
        // Mandatory
        X500Principal requesterIssuer = new X500Principal("CN=jscep.org,DC=Test Deployment,DC=OpenXPKI,DC=org");
        BigInteger serial = BigInteger.ONE;
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1); // yesterday
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.DATE, +2); // tomorrow
        Date notAfter = calendar.getTime();
        X500Principal requesterSubject = new X500Principal("CN=jscep.org,DC=Test Deployment,DC=OpenXPKI,DC=org"); // doesn't need to be the same as issuer
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(requesterIssuer, serial, notBefore, notAfter, requesterSubject, ownCertificateKeyPair.getPublic());

        String sigAlg = getSignatureAlgo(client);
        JcaContentSignerBuilder certSignerBuilder = new JcaContentSignerBuilder(sigAlg); // from above
        ContentSigner certSigner = certSignerBuilder.build(ownCertificateKeyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(certSigner);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        return converter.getCertificate(certHolder);
    }

    private static KeyPair createRandomKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.genKeyPair();
    }

    public static String getSignatureAlgo(Client client) {
        // Usable signature algorithms
        Capabilities caps = client.getCaCapabilities();
        return caps.getStrongestSignatureAlgorithm();
    }

}
