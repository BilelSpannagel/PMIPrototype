import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.jscep.client.Client;
import org.jscep.client.ClientException;
import org.jscep.client.DefaultCallbackHandler;
import org.jscep.client.EnrollmentResponse;
import org.jscep.client.verification.OptimisticCertificateVerifier;
import org.jscep.transaction.TransactionException;
import org.jscep.transport.response.Capabilities;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class name: ${CLASS_NAME}
 * Created by kevin on 08.05.17.
 */
public class Test {

    public static void main(String[] args) throws MalformedURLException, NoSuchAlgorithmException, CertificateException, OperatorCreationException, ClientException, TransactionException {

        CallbackHandler handler = new DefaultCallbackHandler(new OptimisticCertificateVerifier());
        URL url = new URL("http://141.28.105.137/scep/scep");
        // URL url = new URL("http://141.28.104.153/scep/scep");
        Client client = new Client(url, handler);

        // Create key for request
        KeyPair clientKeyPair = createRandomKeyPair();
        X500Principal entitySubject = new X500Principal("CN=jscep.org, L=Cardiff, ST=Wales, C=UK");
        PKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(entitySubject, clientKeyPair.getPublic());

        // Add attributes to the request
        // DERPrintableString password = new DERPrintableString("SecretChallenge");
        // csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, password);

        // Sign the request
        JcaContentSignerBuilder csrSignerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
        ContentSigner csrSigner = csrSignerBuilder.build(clientKeyPair.getPrivate());
        PKCS10CertificationRequest csr = csrBuilder.build(csrSigner);

        // Create a self signed certificate for communication
        KeyPair jscepKeyPair = createRandomKeyPair();
        X509Certificate ownCertificate = createOwnCertificate(jscepKeyPair, client);

        EnrollmentResponse res = client.enrol(ownCertificate, jscepKeyPair.getPrivate(), csr);
        System.out.println(res.isPending());
    }

    private static X509Certificate createOwnCertificate(KeyPair ownCertificateKeyPair, Client client) throws CertificateException, OperatorCreationException {
        // Mandatory
        X500Principal requesterIssuer = new X500Principal("CN=jscep.org, L=Cardiff, ST=Wales, C=UK");
        BigInteger serial = BigInteger.ONE;
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1); // yesterday
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.DATE, +2); // tomorrow
        Date notAfter = calendar.getTime();
        X500Principal requesterSubject = new X500Principal("CN=jscep.org, L=Cardiff, ST=Wales, C=UK"); // doesn't need to be the same as issuer
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
