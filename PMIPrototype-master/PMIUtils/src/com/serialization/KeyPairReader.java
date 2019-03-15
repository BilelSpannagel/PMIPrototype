package com.serialization;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Class name: ${CLASS_NAME}
 * Created by kevin on 06.05.17.
 */
public class KeyPairReader {

    public static KeyPair readKeyPair(String publicFileName, String privateFileName) throws Exception {
        PrivateKey  privateKey = readPrivateKey(privateFileName);
        PublicKey publicKey = readPublicKey(publicFileName);
        return new KeyPair(publicKey, privateKey);
    }

    public static PrivateKey readPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static PublicKey readPublicKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
