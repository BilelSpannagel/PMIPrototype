import com.serialization.*;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by kevin on 05.05.17.
 */
public class SerializationTest {

    @Test
    void attributeCertificateRequest() throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException, ClassNotFoundException, OperatorCreationException {

        KeyPair keyPair = createRandomKeyPair();
        X509Certificate cert = createCertificate(new X500Principal("CN=jscep.org, L=Cardiff, ST=Wales, C=UK"), keyPair);

        AttributeCertificateRequest request = new AttributeCertificateRequest(cert, new String[]{"Room1", "Room2"});
        assertEquals("Room1", request.getAttributes()[0]);
        assertEquals("Room2", request.getAttributes()[1]);
        assertEquals(cert, request.getCertificate());

        // Serialization
        String serialized = ObjectSerializer.toString(request);
        assertNotNull(serialized);

        // Deserialization
        AttributeCertificateRequest deserialized = ObjectDeserializer.fromString(serialized);
        assertNotNull(deserialized);
        assertEquals(request.getAttributes()[0], deserialized.getAttributes()[0]);
        assertEquals(request.getAttributes()[1], deserialized.getAttributes()[1]);
        assertEquals(request.getAttributes().length, deserialized.getAttributes().length);

        assertEquals(cert.getSerialNumber(), deserialized.getCertificate().getSerialNumber());
    }


    @Test
    void serializeAndDeserialize() {
        SimpleCertificate cert1 = new SimpleCertificate("1234", "secret", "John Doe");
        SimpleCertificate cert2 = new SimpleCertificate("2345", "secret", "Jane Doe");
        try {

            String serializedCert1 = ObjectSerializer.toString(cert1);
            SimpleCertificate deserializedCert1 = ObjectDeserializer.fromString(serializedCert1);
            assertEquals(cert1.getOwner(), deserializedCert1.getOwner());
            assertEquals(cert1.getPublicKey(), deserializedCert1.getPublicKey());
            assertEquals(cert1.getSerialNumber(), deserializedCert1.getSerialNumber());

            String serializedCert2 = ObjectSerializer.toString(cert2);
            SimpleCertificate deserializedCert2 = ObjectDeserializer.fromString(serializedCert2);
            assertEquals(cert2.getOwner(), deserializedCert2.getOwner());
            assertEquals(cert2.getPublicKey(), deserializedCert2.getPublicKey());
            assertEquals(cert2.getSerialNumber(), deserializedCert2.getSerialNumber());

        } catch (IOException | ClassNotFoundException e) {
            fail(e.getMessage());
        }
    }

    @Test
    void readKeyPair() throws Exception {
        String privateFileName = "./out/test/PMIUtils/keys/private_key.der";
        String publicFileName = "./out/test/PMIUtils/keys/public_key.der";

        PrivateKey privateKey = KeyPairReader.readPrivateKey(privateFileName);
        assertNotNull(privateKey);

        PublicKey publicKey = KeyPairReader.readPublicKey(publicFileName);
        assertNotNull(publicKey);

        KeyPair keyPair = KeyPairReader.readKeyPair(publicFileName, privateFileName);
        assertNotNull(keyPair);

        assertEquals(privateKey.getAlgorithm(), keyPair.getPrivate().getAlgorithm());
        assertEquals(privateKey.getFormat(), keyPair.getPrivate().getFormat());

        assertEquals(publicKey.getAlgorithm(), keyPair.getPublic().getAlgorithm());
        assertEquals(publicKey.getFormat(), keyPair.getPublic().getFormat());

        assertEquals(privateKey, keyPair.getPrivate());
        assertEquals(publicKey, keyPair.getPublic());
    }

    @Test
    void serializeCSR() throws NoSuchAlgorithmException, OperatorCreationException, IOException {
        KeyPair requestKeyPair = SerializationTest.createRandomKeyPair();
        X500Principal entitySubject = new X500Principal("CN=jscep.org, L=Cardiff, ST=Wales, C=UK");
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(entitySubject, requestKeyPair.getPublic());

        // Sign the request
        JcaContentSignerBuilder csrSignerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
        ContentSigner csrSigner = csrSignerBuilder.build(requestKeyPair.getPrivate());
        PKCS10CertificationRequest csr = csrBuilder.build(csrSigner);

        // Serialize to base64 string
        String serialized = ObjectSerializer.toString(csr);
        assertNotNull(serialized);

        // Deserialize from base64 string
        PKCS10CertificationRequest deserialized = ObjectDeserializer.fromCSRString(serialized);
        assertNotNull(deserialized);

        assertTrue(csr.equals(deserialized));
    }

    private static KeyPair createRandomKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.genKeyPair();
    }

    private static X509Certificate createCertificate(X500Principal subject, KeyPair jscepKeyPair) throws CertificateException, OperatorCreationException {
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
        String sigAlg = "SHA1withRSA";
        JcaContentSignerBuilder certSignerBuilder = new JcaContentSignerBuilder(sigAlg); // from above
        ContentSigner certSigner = certSignerBuilder.build(jscepKeyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(certSigner);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        return converter.getCertificate(certHolder);
    }

}
