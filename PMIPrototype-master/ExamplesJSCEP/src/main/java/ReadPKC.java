import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.jscep.client.Client;
import org.jscep.client.DefaultCallbackHandler;
import org.jscep.client.EnrollmentResponse;
import org.jscep.client.verification.CachingCertificateVerifier;
import org.jscep.client.verification.CertificateVerifier;
import org.jscep.client.verification.ConsoleCertificateVerifier;
import org.jscep.client.verification.OptimisticCertificateVerifier;
import org.jscep.transport.response.Capabilities;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;

/**
 * Class name: ${CLASS_NAME}
 * Created by kevin on 06.05.17.
 */
public class ReadPKC {

    public static void main(String[] args) throws Exception {

        System.out.println("PMI Facade start...");
        URL url = new URL("http://141.28.105.137/scep/scep");
        // URL url = new URL("http://141.28.104.153/scep/scep");

        CertificateVerifier consoleVerifier = new ConsoleCertificateVerifier();
        CertificateVerifier verifier = new OptimisticCertificateVerifier(); // new CachingCertificateVerifier(consoleVerifier);
        CallbackHandler handler = new DefaultCallbackHandler(verifier);

        Client client = new Client(url, handler);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair requesterKeyPair = keyPairGenerator.genKeyPair();

        // Mandatory
        X500Principal requesterIssuer = new X500Principal("CN=jscep.org, L=Cardiff, ST=Wales, C=UK");
        BigInteger serial = BigInteger.ONE;
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1); // yesterday
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.DATE, +2); // tomorrow
        Date notAfter = calendar.getTime();
        X500Principal requesterSubject = new X500Principal("CN=jscep.org, L=Cardiff, ST=Wales, C=UK"); // doesn't need to be the same as issuer
        PublicKey requesterPubKey = requesterKeyPair.getPublic(); // from generated key pair
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(requesterIssuer, serial, notBefore, notAfter, requesterSubject, requesterPubKey);

        // Get signature algorithm
        Capabilities caps = client.getCaCapabilities();
        String sigAlg = caps.getStrongestSignatureAlgorithm();

        // Self Signing
        PrivateKey requesterPrivKey = requesterKeyPair.getPrivate(); // from generated key pair
        JcaContentSignerBuilder certSignerBuilder = new JcaContentSignerBuilder(sigAlg); // from above
        ContentSigner certSigner = certSignerBuilder.build(requesterPrivKey);
        X509CertificateHolder certHolder = certBuilder.build(certSigner);


        // extract the JCA-compatible certificate
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        X509Certificate requesterCert = converter.getCertificate(certHolder);

        //set password and cast it
        String password = "SecretChallenge";
        DERPrintableString cpSet = new DERPrintableString(new String(password));
        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(requesterPubKey.getEncoded());

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(
                "SHA1withRSA");
        ContentSigner signer;
        try {
            signer = signerBuilder.build(requesterPrivKey);
        } catch (OperatorCreationException e) {
            IOException ioe = new IOException();
            ioe.initCause(e);

            throw ioe;
        }
        //generate certificate signing request
        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(X500Name.getInstance(requesterSubject.getEncoded()),pkInfo);
        //set Scep server password
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, cpSet);

        PKCS10CertificationRequest csr = builder.build(signer);
        //Send the enrollment request
        System.out.println("Zertifikat wird gesendet");
        EnrollmentResponse response = client.enrol(requesterCert,requesterPrivKey,csr);
        System.out.println(response);

        X500Principal entityprincipal = new X500Principal(requesterIssuer.getEncoded());
        //Polling for a Pending Enrollment
        response = client.poll(requesterCert,requesterKeyPair.getPrivate(),entityprincipal,response.getTransactionId());
        //response = client.poll(requesterCert, requesterPrivKey, requesterSubject);
        System.out.println("response wurde gesendet, 13 Sekunden Zeit um zu genehmigen");
        // Thread.sleep(20000);
        CertStore store = response.getCertStore();
        Collection<? extends Certificate> certs = store.getCertificates(null);
        java.security.cert.Certificate[] chain = new java.security.cert.Certificate[certs.size()];

        int i = 0;
        for (java.security.cert.Certificate certificate : certs){
            chain[i++]= certificate;
            System.out.println("Zertifikate"+response);
            System.out.println(certificate);
        }

    }
}
