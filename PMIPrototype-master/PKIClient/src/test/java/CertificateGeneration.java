import hfu.pki.base.CertificationAuthority;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static junit.framework.TestCase.assertNotNull;

public class CertificateGeneration {

    @BeforeClass
    public static void beforeClass() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    @Test
    public void certificateCreationWithCSR() throws NoSuchProviderException, NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException {

        // CSR content
        X500Principal entitySubject = new X500Principal("CN=Bilel, O=HFU, C=DE");
        KeyPairGenerator kPG = KeyPairGenerator.getInstance("RSA", "BC");
        kPG.initialize(1024, new SecureRandom());
        KeyPair keyPair = kPG.generateKeyPair();

        // CSR builder
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(entitySubject, keyPair.getPublic());

        // Sign the request
        JcaContentSignerBuilder csrSignerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
        ContentSigner csrSigner = csrSignerBuilder.build(keyPair.getPrivate());

        // Create request
        PKCS10CertificationRequest csr = csrBuilder.build(csrSigner);

        // Trigger certificate creation from CA
        CertificationAuthority ca = new CertificationAuthority();
        X509Certificate certificate = ca.issueCertificate(csr);

        // TODO: this should not be null
        assertNotNull(certificate);
    }

}
