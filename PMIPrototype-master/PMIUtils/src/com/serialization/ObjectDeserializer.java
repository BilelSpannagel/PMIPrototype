package com.serialization;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.io.*;
import java.util.Base64;

/**
 * Created by kevin on 05.05.17.
 */
public class ObjectDeserializer {

    /**
     * Read the object from Base64 string.
     */
    public static <T extends Serializable> T fromString(String s) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getUrlDecoder().decode(s);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object o = ois.readObject();
        ois.close();
        return (T)o;
    }

    /**
     * Read the certificate request from Base64 string.
     */
    // CSR: Certificate Singing Request
    public static PKCS10CertificationRequest fromCSRString(String s) throws IOException {
        String decodedString = new String(Base64.getUrlDecoder().decode(s));
        PEMParser pemParser = new PEMParser(new StringReader(decodedString));
        Object parsedObj = pemParser.readObject();
        return parsedObj instanceof PKCS10CertificationRequest ? (PKCS10CertificationRequest)parsedObj : null;
    }

}
