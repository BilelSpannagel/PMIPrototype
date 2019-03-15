

import org.bouncycastle.cert.selector.X509CertificateHolderSelector;
import org.jscep.client.Client;
import org.jscep.client.DefaultCallbackHandler;
import org.jscep.client.verification.CertificateVerifier;
import org.jscep.client.verification.ConsoleCertificateVerifier;
import org.jscep.client.verification.OptimisticCertificateVerifier;
import sun.security.x509.X509CertImpl;

import javax.security.auth.callback.CallbackHandler;
import java.net.URL;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CollectionCertStoreParameters;

/**
 * Created by kevin on 22.04.17.
 */
public class MainCACertificates {
    public static void main(String[] args) throws Exception {

        URL url = new URL("http://141.28.105.137/scep/scep");
        CertificateVerifier verifier = new OptimisticCertificateVerifier(); // new ConsoleCertificateVerifier();
        CallbackHandler handler = new DefaultCallbackHandler(verifier);

        Client client = new Client(url, handler);
        CertStore caCertificate = client.getCaCertificate();
        System.out.println(caCertificate);

        for (Object o : (((CollectionCertStoreParameters) caCertificate.getCertStoreParameters()).getCollection())) {
            System.out.println("Certificate:");
            System.out.println(o);
        }

        System.out.println("Erster test");

    }
}
