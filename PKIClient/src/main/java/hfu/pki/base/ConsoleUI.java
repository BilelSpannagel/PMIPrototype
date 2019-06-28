package hfu.pki.base;

import hfu.pki.database.DatabaseFacade;
import hfu.pki.database.JDBC;
import hfu.pki.database.JSONconverter;
import hfu.pki.utils.Utils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

public class ConsoleUI {
    private static String m = "";
    static void mainMenu() throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, CRLException, IOException, OperatorCreationException, NoSuchProviderException {
        Scanner scanner = new Scanner(System.in);
        while (m.equals("e") != true){
            System.out.println("############ Main Menu ############");
            System.out.println("a. Show all certificates");
            System.out.println("b. Search for a certificate");
            System.out.println("c. Revoke a certificate");
            System.out.println("d. Create a certificate request");
            System.out.println("e. Exit");
            System.out.println("###################################");
            m = scanner.next();
            switch(m){
                case "a": {
                    System.out.println(JDBC.queryCollection(null));
                    break;
                }
                case "b": {
                    System.out.println("Please enter the certificate ID: ");
                    String n = scanner.next();
                    System.out.println(JDBC.queryCollection(n));
                    break;
                }
                case "c": {
                    System.out.println("Please enter the certificate ID: ");
                    String n = scanner.next();
                    DatabaseFacade dF = new DatabaseFacade();
                    ValidationAuthority vA = new ValidationAuthority(dF);
                    vA.addToCRL(JSONconverter.convertFromJSONToCertificate(JDBC.queryCollection(n)), CRLReason.privilegeWithdrawn);
                    System.out.println("Certificate has been revoked");
                    break;
                }
                case "d": {
                    DatabaseFacade dF = new DatabaseFacade();
                    CertificationAuthority cA = new CertificationAuthority(dF);
                    RegistrationAuthority rA = new RegistrationAuthority(cA);
                    KeyPair pair = Utils.createKeyPair();
                    String cn = "C=";
                    System.out.println("Country code: ");
                    String n = scanner.next();
                    cn = cn + n + ",";
                    System.out.println("Organisation: ");
                    n = scanner.next();
                    cn = cn + " O=" + n + ",";
                    System.out.println("Clear name: ");
                    n = scanner.next();
                    cn = cn + " CN=" + n;
                    rA.issueCertificate(new X500Name(cn), pair.getPublic());
                    break;
                }
                case "e": {
                    break;
                }
            }
        }
        scanner.close();
    }
}
