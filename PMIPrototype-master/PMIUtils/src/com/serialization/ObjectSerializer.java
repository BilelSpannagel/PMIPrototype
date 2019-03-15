package com.serialization;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import java.io.*;
import java.util.Base64;

/**
 * Created by kevin on 05.05.17.
 */
public class ObjectSerializer {

    /**
     * Write the object to a Base64 string.
     */
    public static String toString(Serializable o) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(o);
        oos.close();
        return Base64.getUrlEncoder().encodeToString(baos.toByteArray());
    }

    /**
    * Write the certificate to a Base64 string.
    */
    public static String toString(PKCS10CertificationRequest o) throws IOException {
        // TODO: check JcaPKCS10CertificationRequest parsing necessary?
        StringWriter writer = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(o);
        pemWriter.close();
        String serializedObj = writer.toString();

        // encode string with base64
        return Base64.getUrlEncoder().encodeToString(serializedObj.getBytes());
    }

}
