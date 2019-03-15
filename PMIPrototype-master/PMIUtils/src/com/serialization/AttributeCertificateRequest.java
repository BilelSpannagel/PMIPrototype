package com.serialization;

import java.io.Serializable;
import java.security.cert.X509Certificate;

/**
 * Created by rz on 20.06.17.
 */
public class AttributeCertificateRequest implements Serializable {

    private final X509Certificate certificate;
    private final String[] attributes;

    public AttributeCertificateRequest(X509Certificate certificate, String[] attributes) {
        this.certificate = certificate;
        this.attributes = attributes;
    }

    public X509Certificate getCertificate() {
        return this.certificate;
    }

    public String[] getAttributes() {
        return this.attributes;
    }
}
