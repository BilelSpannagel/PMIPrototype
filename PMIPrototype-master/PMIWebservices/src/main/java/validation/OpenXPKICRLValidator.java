package validation;

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
import org.jscep.transport.response.Capabilities;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

/**
 * Created by kevin on 16.05.2017.
 */
public class OpenXPKICRLValidator {

    public void verifyCertificateCRLs(X509Certificate cert) throws CertificateValidationException {

        try {
            URL url = new URL("http://141.28.104.153/scep/scep");

            CertificateVerifier verifier = new OptimisticCertificateVerifier(); // new ConsoleCertificateVerifier();
            CallbackHandler handler = new DefaultCallbackHandler(verifier);
            Client jscepClient = new Client(url, handler);

            KeyPair jscepKeyPair = createRandomKeyPair();
            X509Certificate jscepCertificate = createOwnCertificate(jscepKeyPair, jscepClient);

            X509CRL crl = downloadCRL(jscepClient, jscepCertificate, jscepKeyPair, cert);
            if (crl.isRevoked(cert)) {
                throw new CertificateValidationException(
                        "The certificate is revoked by CRL: " + crl);
            }
        } catch (Exception e) {
            throw new CertificateValidationException("Problem while downloading the certificate:\n" + e.getMessage());
        }

    }

    private X509CRL downloadCRL(Client jscepClient, X509Certificate jscepCertificate, KeyPair jscepKeyPair, X509Certificate certificateToCheck) throws MalformedURLException, ClientException, OperationFailureException {
        X509CRL crl = jscepClient.getRevocationList(jscepCertificate, jscepKeyPair.getPrivate(), certificateToCheck.getIssuerX500Principal(), certificateToCheck.getSerialNumber());
        return crl;
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

    private static String getSignatureAlgo(Client client) {
        // Usable signature algorithms
        Capabilities caps = client.getCaCapabilities();
        return caps.getStrongestSignatureAlgorithm();
    }
}
