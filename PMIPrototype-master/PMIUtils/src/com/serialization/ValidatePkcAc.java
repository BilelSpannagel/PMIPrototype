package com.serialization;

import java.io.Serializable;
import java.security.cert.X509Certificate;

/**
 * Created by rz on 20.06.17.
 */
public class ValidatePkcAc implements Serializable {

    private final X509Certificate certificate;
    private final String acertificate;

    public ValidatePkcAc(X509Certificate certificate, String acertificate) {
        this.certificate = certificate;
        this.acertificate = acertificate;
    }

    public X509Certificate getCertificate() {
        return this.certificate;
    }

    public String getAcertificate() {
        return this.acertificate;
    }
}
