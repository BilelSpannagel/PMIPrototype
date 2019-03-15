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
import org.jscep.client.ClientException;
import org.jscep.client.DefaultCallbackHandler;
import org.jscep.client.EnrollmentResponse;
import org.jscep.client.verification.CertificateVerifier;
import org.jscep.client.verification.ConsoleCertificateVerifier;
import org.jscep.client.verification.OptimisticCertificateVerifier;
import org.jscep.transaction.TransactionException;
import org.jscep.transport.response.Capabilities;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.util.Calendar;
import java.util.Date;

/**
 * Created by kevin on 22.04.17.
 */
public class MainRequestCertificate {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException, ClientException, TransactionException, CertStoreException, InterruptedException {

        URL url = new URL("http://141.28.105.137/scep/scep");
        // org.jscep.validation.CertificateVerifier verifier = new ConsoleCertificateVerifier();
        CallbackHandler handler = new DefaultCallbackHandler(new OptimisticCertificateVerifier());

        Client client = new Client(url, handler);

        // Client key pair
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
        // Optional extensions
        // certBuilder.addExtension(X509Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));

        // Get signature algorithm
        Capabilities caps = client.getCaCapabilities();
        String sigAlg = caps.getStrongestSignatureAlgorithm();

        // Self Signing
        PrivateKey requesterPrivKey = requesterKeyPair.getPrivate(); // from generated key pair
        JcaContentSignerBuilder certSignerBuilder = new JcaContentSignerBuilder(sigAlg); // from above
        ContentSigner certSigner = certSignerBuilder.build(requesterPrivKey);
        X509CertificateHolder certHolder = certBuilder.build(certSigner);

        // Certificate for requesting signing
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        X509Certificate requesterCert = converter.getCertificate(certHolder);

        String password = "SecretChallenge";
        DERPrintableString cpSet = new DERPrintableString(new String(password));
        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(requesterPubKey.getEncoded());

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
        ContentSigner signer;
        try {
            signer = signerBuilder.build(requesterPrivKey);
        } catch (OperatorCreationException e) {
            IOException ioe = new IOException();
            ioe.initCause(e);

            throw ioe;
        }

        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(
                X500Name.getInstance(requesterSubject.getEncoded()), pkInfo);
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                cpSet);

        PKCS10CertificationRequest csr = builder.build(signer);

        EnrollmentResponse response = client.enrol(requesterCert, requesterPrivKey, csr);
        System.out.println(response);

        //X509Certificate test = (X509Certificate) response;

        // Thread.sleep(30000);

        X500Principal entityPrincipal = new X500Principal(requesterIssuer.getEncoded());
        response = client.poll(requesterCert, requesterKeyPair.getPrivate(), entityPrincipal,
                response.getTransactionId());

        for (java.security.cert.Certificate o : response.getCertStore().getCertificates(null)) {
            System.out.println("Certificate:");
            System.out.println(o);
        }

       System.out.println(response);
    }

}
