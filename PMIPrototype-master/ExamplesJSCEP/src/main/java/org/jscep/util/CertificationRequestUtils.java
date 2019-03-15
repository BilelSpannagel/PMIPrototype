package org.jscep.util;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * This class is used for performing utility operations on
 * <tt>CertificationRequest</tt> instances.
 */
public final class CertificationRequestUtils {
    private CertificationRequestUtils() {
    }

    /**
     * Extracts the <tt>PublicKey</tt> from the provided CSR.
     * <p>
     * This method will throw a {@link RuntimeException} if the JRE is missing
     * the RSA algorithm, which is a required algorithm as defined by the JCA.
     * 
     * @param csr
     *            the CSR to extract from.
     * @return the extracted <tt>PublicKey</tt>
     * @throws InvalidKeySpecException
     *             if the CSR is not using an RSA key.
     * @throws IOException
     *             if there is an error extracting the <tt>PublicKey</tt>
     *             parameters.
     */
    public static PublicKey getPublicKey(final PKCS10CertificationRequest csr)
            throws InvalidKeySpecException, IOException {
        SubjectPublicKeyInfo pubKeyInfo = csr.getSubjectPublicKeyInfo();
        RSAKeyParameters keyParams = (RSAKeyParameters) PublicKeyFactory
                .createKey(pubKeyInfo);
        KeySpec keySpec = new RSAPublicKeySpec(keyParams.getModulus(),
                keyParams.getExponent());

        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return kf.generatePublic(keySpec);
    }

    /**
     * Extracts the <tt>Challenge password</tt> from the provided CSR.
     * <p>
     * 
     * @param csr
     *            the CSR to extract from.
     * @return the extracted <tt>Challenge password</tt>
     */
    public static String getChallengePassword(final PKCS10CertificationRequest csr) {
        Attribute[] attrs = csr.getAttributes();
        for (Attribute attr : attrs) {
            if (attr.getAttrType().equals(
                    PKCSObjectIdentifiers.pkcs_9_at_challengePassword)) {
                DERPrintableString challangePassword = (DERPrintableString) attr
                        .getAttrValues().getObjectAt(0);
                return challangePassword.getString();
            }
        }
        return null;
    }


}
