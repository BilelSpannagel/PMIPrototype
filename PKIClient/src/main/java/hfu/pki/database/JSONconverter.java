package hfu.pki.database;

import com.mongodb.BasicDBObject;
import com.mongodb.DBObject;
import hfu.pki.utils.Utils;
import org.bson.Document;
import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class JSONconverter {
    public static Document convertToJSONFromFile(String filename) throws IOException, CertificateException {
        X509Certificate certificateFromPEM = Utils.loadCertificateFromPEM(filename);
        BASE64Encoder encoder = new BASE64Encoder();
        byte[] certificateAsBytes = certificateFromPEM.getEncoded();
        String certificateAsString = new String(encoder.encode(certificateAsBytes));
        Document newJSON = new Document();
        newJSON.put("id", new String(certificateFromPEM.getSerialNumber().toByteArray()));
        newJSON.put("certificate", X509Factory.BEGIN_CERT + certificateAsString + X509Factory.END_CERT);
        return newJSON;
    }
    public static Document convertToJSONFromCertificate(X509Certificate certificate) throws CertificateEncodingException {
        BASE64Encoder encoder = new BASE64Encoder();
        byte[] certificateAsBytes = certificate.getEncoded();
        String certificateAsString = new String(encoder.encode(certificateAsBytes));
        Document newJSON = new Document();
        newJSON.put("_id", new String(certificate.getSerialNumber().toByteArray()));
        newJSON.put("certificate", X509Factory.BEGIN_CERT + certificateAsString + X509Factory.END_CERT);
        return newJSON;
    }
    public static X509Certificate convertFromJSONToCertificate(Document file) throws CertificateException {
        String fileAsString = file.get("certificate").toString();
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        byte[] decoded = Base64.getMimeDecoder().decode(fileAsString.replaceAll(X509Factory.BEGIN_CERT, "").replaceAll(X509Factory.END_CERT, ""));
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));
    }
}
