package com.serialization;

/**
 * Created by kevin on 05.05.17.
 */
public class SimpleCertificate implements java.io.Serializable {
    private String serialNumber;
    private String publicKey;
    private String owner;

    public SimpleCertificate(String serialNumber, String publicKey, String owner) {
        this.serialNumber = serialNumber;
        this.publicKey = publicKey;
        this.owner = owner;
    }

    public String getSerialNumber() {
        return this.serialNumber;
    }

    public String getPublicKey() {
        return this.publicKey;
    }

    public String getOwner() {
        return this.owner;
    }
}
