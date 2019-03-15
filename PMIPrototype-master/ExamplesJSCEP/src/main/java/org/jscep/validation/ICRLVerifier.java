package org.jscep.validation;

import java.security.cert.X509Certificate;

/**
 * Created by kevin on 16.05.2017.
 */
public interface ICRLVerifier {

    void verifyCertificateCRLs(X509Certificate cert) throws CertificateVerificationException;
}
