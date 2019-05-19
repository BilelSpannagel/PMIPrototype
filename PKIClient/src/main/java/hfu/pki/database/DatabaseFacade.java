package hfu.pki.database;

import java.security.cert.X509Certificate;

public class DatabaseFacade {


    public boolean storeCertificate(X509Certificate certificate) {
        return false;
    }

    public boolean revokeCertificate(String serialNumber) {
        return false;
    }

    public X509Certificate getCertificate(String serialNumber) {
        return null;
    }
}
