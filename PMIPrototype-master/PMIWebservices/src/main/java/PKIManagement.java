import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.client.Client;
import org.jscep.client.ClientException;
import org.jscep.client.DefaultCallbackHandler;
import org.jscep.client.EnrollmentResponse;
import org.jscep.client.verification.CertificateVerifier;
import org.jscep.client.verification.OptimisticCertificateVerifier;
import org.jscep.transaction.OperationFailureException;
import org.jscep.transaction.TransactionException;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.response.Capabilities;
import validation.CertificateValidationException;
import validation.CertificateValidator;
import javax.print.attribute.SetOfIntegerSyntax;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Class name: ${CLASS_NAME}
 * Created by kevin on 08.05.17.
 */
class PKIManagement {

    private final KeyPair jscepKeyPair;
    private final X500Principal subject;
    private final X509Certificate certificate;
    private final Client client;

    X500Principal getSubject() {
        return subject;
    }


    PKIManagement() throws MalformedURLException, NoSuchAlgorithmException, CertificateException, OperatorCreationException {
        CertificateVerifier verifier = new OptimisticCertificateVerifier();
        CallbackHandler handler = new DefaultCallbackHandler(verifier);
        URL url = new URL("http://141.28.104.153/scep/scep");
        // URL url = new URL("http://141.28.105.137/scep/scep");
        client = new Client(url, handler);

        // Create key pair and certificate for the communication with the SCEP server
        jscepKeyPair = createRandomKeyPair();
        subject = new X500Principal("CN=jscep.org, L=Cardiff, ST=Wales, C=UK");
        certificate = createCertificate(subject, jscepKeyPair, client);
    }


    EnrollmentResponse enrol(PKCS10CertificationRequest csr) throws ClientException, TransactionException {
        // csr.getSubject(); --> create a new subject
        return client.enrol(certificate, jscepKeyPair.getPrivate(), csr);
    }

    X509Certificate getCertificate(BigInteger serialNumber) {
        try {
            CertStore store = client.getCertificate(certificate, jscepKeyPair.getPrivate(), serialNumber);
            return getFirstCertificateFromCertStore(store);
        } catch (ClientException | OperationFailureException e) {
            e.printStackTrace();
            return null;
        }
    }

    X509Certificate pollCertificate(X500Principal subject, TransactionId transactionId) {
        try {
            EnrollmentResponse response = client.poll(certificate, jscepKeyPair.getPrivate(), subject, transactionId);
            return response.isSuccess() ? getFirstCertificateFromCertStore(response.getCertStore()) : null;
        } catch (ClientException | TransactionException e) {
            e.printStackTrace();
            return null;
        }
    }

    String validateCertificate(X509Certificate certificateToValidate) throws ClientException {

        String validationResult = "";

        try {
            CertStore caCertStore  = client.getCaCertificate();
            Collection<? extends Certificate> certificates = caCertStore.getCertificates(null);
            Set<X509Certificate> caCertificates = certificates.stream().map(c -> (X509Certificate)c).collect(Collectors.toSet());
            PKIXCertPathBuilderResult pathBuilderResult = CertificateValidator.verifyCertificate(certificateToValidate, caCertificates);
            validationResult += "Validation was successful.\n";
            //validationResult += pathBuilderResult;
        } catch (Exception e) {
            e.printStackTrace();
            validationResult += "Validation was not successful.\n";
        }

        return validationResult;
    }

    /**
     * TODO: change this method, so that the subject names of the self signed certificate
     * and from the request are equal
     * Note: if you're using a self-signed certificate,
     * your certificate subject X500 name must be the same as
     * the subject in your certificate-signing request.
     */
    private static X509Certificate createCertificate(X500Principal subject, KeyPair jscepKeyPair, Client client) throws CertificateException, OperatorCreationException {
        // Mandatory
        X500Principal requesterIssuer = subject;
        BigInteger serial = BigInteger.ONE;
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1); // yesterday
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.DATE, +2); // tomorrow
        Date notAfter = calendar.getTime();
        X500Principal requesterSubject = new X500Principal("CN=jscep.org, L=Cardiff, ST=Wales, C=UK"); // doesn't need to be the same as subject
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(requesterIssuer, serial, notBefore, notAfter, requesterSubject, jscepKeyPair.getPublic());

        // Create own certificate
        String sigAlg = getSignatureAlgo(client);
        JcaContentSignerBuilder certSignerBuilder = new JcaContentSignerBuilder(sigAlg); // from above
        ContentSigner certSigner = certSignerBuilder.build(jscepKeyPair.getPrivate());
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

    private static X509Certificate getFirstCertificateFromCertStore(CertStore store) {
        if (store == null) {return null; }

        try {
            Collection<? extends Certificate> certs = store.getCertificates(null);
            for (Certificate c : certs) {
                if (c instanceof X509Certificate) {
                    return (X509Certificate)c;
                }
            }
            return  null;
        } catch (CertStoreException e) {
            e.printStackTrace();
            return null;
        }
    }
}
