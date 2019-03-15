import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import com.sun.xml.internal.messaging.saaj.util.ByteInputStream;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.RoleSyntax;
import org.bouncycastle.asn1.x509.X509AttributeIdentifiers;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.AttributeCertificateIssuer;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v2AttributeCertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaAttributeCertificateIssuer;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509AttrCertParser;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.x509.X509Attribute;
import org.bouncycastle.x509.X509V2AttributeCertificate;
/**
 * Created by emre on 08.06.17.
 */
//Simple Example to generate an Attribute Certificate

public class AttributeCertificateExample {
    //generate the AC issuer's certificate
    public static X509Certificate createAcIssuerCert(
            PublicKey pubKey, PrivateKey privKey) throws Exception {
        //signers name
        String issuer = "C=AU, O=The Legion of the Bouncy Castle, OU=Bouncy Primary Certificate";
        //subject name - same as we are self signed
        String subject = "C=AU, O=The Legion of the Bouncy Castle, OU=Bouncy Primary Certificate";
        //create the certificate version 1
        X509v1CertificateBuilder builderv1 = new JcaX509v1CertificateBuilder(new X500Name(issuer), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30), new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)), new X500Name(subject), pubKey);
        //create Holder
        X509CertificateHolder certHolder = builderv1.build(new JcaContentSignerBuilder("SHA1WithRSA").setProvider("BC").build(privKey));
        //create X509 Certificate
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
        cert.checkValidity(new Date());
        cert.verify(pubKey);
        return cert;
    }
//
    //we generate a certificate signed by our CA's intermediate certificate
    public static X509Certificate createClientCert(
            PublicKey pubKey,
            PrivateKey caPrivKey,
                PublicKey caPubKey) throws Exception {
        //issuer
        String issuer = "C=AU, O=The Legion of the Bouncy Castle, OU=Bouncy Primary Certificate";
        //subject name builder
        X500NameBuilder nameBuilder = new X500NameBuilder();
        nameBuilder.addRDN(BCStyle.C, "AU");
        nameBuilder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        nameBuilder.addRDN(BCStyle.L, "Melbourne");
        nameBuilder.addRDN(BCStyle.CN, "Eric H. Echidna");
        nameBuilder.addRDN(BCStyle.EmailAddress, "emre.guerkan@gmx.de");

        //create the certificate version 3
        X509v3CertificateBuilder builderv3 = new JcaX509v3CertificateBuilder(new X500Name(issuer), BigInteger.valueOf(2), new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30), new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)), nameBuilder.build(), pubKey);
        builderv3.addExtension(
                MiscObjectIdentifiers.netscapeCertType, false, new NetscapeCertType(NetscapeCertType.objectSigning | NetscapeCertType.smime));
        X509CertificateHolder certHolder = builderv3.build(new JcaContentSignerBuilder("SHA1WithRSA").setProvider("BC").build(caPrivKey));
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
        cert.checkValidity(new Date());
        cert.verify(caPubKey);
        return cert;
    }

    public static void main(String args[]) throws Exception {


        int serial = Database.GetNextFreeSerialNumber();
        System.out.println(serial);

        Security.addProvider(new BouncyCastleProvider());
        //personal keys
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
                new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
                new BigInteger("11", 16));

        RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
                new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
                new BigInteger("11", 16),
                new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
                new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
                new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
                new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
                new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
                new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));
        //ca keys
        RSAPublicKeySpec caPubKeySpec = new RSAPublicKeySpec(
                new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16),
                new BigInteger("11", 16));

        RSAPrivateCrtKeySpec caPrivKeySpec = new RSAPrivateCrtKeySpec(
                new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16),
                new BigInteger("11", 16),
                new BigInteger("92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619", 16),
                new BigInteger("f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03", 16),
                new BigInteger("b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb696fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947", 16),
                new BigInteger("1d1a2d3ca8e52068b3094d501c9a842fec37f54db16e9a67070a8b3f53cc03d4257ad252a1a640eadd603724d7bf3737914b544ae332eedf4f34436cac25ceb5", 16),
                new BigInteger("6c929e4e81672fef49d9c825163fec97c4b7ba7acb26c0824638ac22605d7201c94625770984f78a56e6e25904fe7db407099cad9b14588841b94f5ab498dded", 16),
                new BigInteger("dae7651ee69ad1d081ec5e7188ae126f6004ff39556bde90e0b870962fa7b926d070686d8244fe5a9aa709a95686a104614834b0ada4b10f53197a5cb4c97339", 16));
        //set up the keys
        KeyFactory fact = KeyFactory.getInstance("RSA", "BC");
        PrivateKey caPrivKey = fact.generatePrivate(caPrivKeySpec);
        PublicKey caPubKey = fact.generatePublic(caPubKeySpec);
        PrivateKey privKey = fact.generatePrivate(privKeySpec);
        PublicKey pubKey = fact.generatePublic(pubKeySpec);
            /*we are using the CA certificate for both the client certificate and the attribute certificate.
            In practice the CA for the attribute certificate should be different to that of the client certificate
             */
        X509Certificate caCert = createAcIssuerCert(caPubKey, caPrivKey);
        System.out.println(caCert.toString());
        X509Certificate clientCert = createClientCert(pubKey, caPrivKey, caPubKey);
        System.out.println(clientCert.toString());
        // Instantiate a new AC generator
        X509v2AttributeCertificateBuilder acBldr = new X509v2AttributeCertificateBuilder(
                new AttributeCertificateHolder(new JcaX509CertificateHolder(clientCert)),
                new JcaAttributeCertificateIssuer(caCert),
                new BigInteger(String.valueOf(serial)),
                new Date(System.currentTimeMillis() - 50000),         // not before
                new Date(System.currentTimeMillis() + 50000)); // not after
        // the actual attributes
        //attribute noch hinzufügen
        GeneralName roleName = new GeneralName(GeneralName.uniformResourceIdentifier, "id://DAU123456789");
        GeneralName nameemre = new GeneralName(GeneralName.dNSName, "hs-furtwangen.de");

        acBldr.addAttribute(X509AttributeIdentifiers.id_at_role, new RoleSyntax(roleName));

        //      finally create the AC
        X509AttributeCertificateHolder att = acBldr.build(new JcaContentSignerBuilder("SHA1WithRSA").setProvider("BC").build(caPrivKey));
        System.out.println(att.toASN1Structure().getAcinfo().toString());


        //
        // starting here, we parse the newly generated AC
        //

        // Holder

        AttributeCertificateHolder h = att.getHolder();
        if (h.match(clientCert)) {
            if (h.getEntityNames() != null) {
                System.out.println(h.getEntityNames().length + " entity names found");
            }
            if (h.getIssuer() != null) {
                System.out.println(h.getIssuer().length + " issuer names found, serial number " + h.getSerialNumber());
            }
            System.out.println("Matches original client x509 cert");
        }

        // Issuer

        AttributeCertificateIssuer issuer = att.getIssuer();
        if (issuer.match(caCert)) {
            if (issuer.getNames() != null) {
                System.out.println(issuer.getNames().length + " entity names found");
            }
            System.out.println("Matches original ca x509 cert");
        }

        // Dates
        System.out.println("valid not before: " + att.getNotBefore());
        System.out.println("valid not before: " + att.getNotAfter());

        // check the dates

        if (att.isValidOn(new Date())) {
            System.out.println("valid now");
        }


        // verify

        if (att.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(caPubKey))) {
            System.out.println("signature valid now");
        }

        // Attribute
        Attribute[] attribs = att.getAttributes();
        System.out.println("cert has " + attribs.length + " attributes:");
        Arrays.stream(attribs).forEach(a ->
                System.out.println(a.getAttrType() + ": " + Arrays.stream(a.getAttributeValues()).map(Object::toString).collect(Collectors.joining(","))));

        for (int i = 0; i < attribs.length; i++) {
            Attribute a = attribs[i];
            System.out.println("OID: " + a.getAttrType());
            // currently we only check for the presence of a 'RoleSyntax' attribute


            if (a.getAttrType().equals("2.5.24.72")) {
                System.out.println("rolesyntax read from cert!");
            }
        }

        byte[] arr = att.getEncoded();
        X509AttributeCertificateHolder holder = new X509AttributeCertificateHolder(arr);
        for (int i = 0; i < holder.getAttributes().length; i++) {
            Attribute attr1 = holder.getAttributes()[i];
            Attribute attr2 = att.getAttributes()[i];
            //Use DLSequence from holder to create a RoleSyntax object
            ASN1Set values1 = attr1.getAttrValues();
            RoleSyntax rl = RoleSyntax.getInstance(attr1.getAttrValues().getObjectAt(0));
            System.out.println("Holder value after decode: " + rl);
            System.out.println("Holder value before encode: " + attr2.getAttrValues());
        }


        BigInteger acSerial = att.getSerialNumber();
        BigInteger pkcSerial = att.getHolder().getSerialNumber();
        Database myDatabase = new Database();
        myDatabase.inserting(acSerial,pkcSerial,Base64.getUrlEncoder().encodeToString(att.getEncoded()));
        //X509AttributeCertificateHolder readCertificate = myDatabase.selecting();
        //System.out.println(readCertificate);
        // displayAC(readCertificate);

    }


      /* public static void displayAC(X509AttributeCertificateHolder attr) {
        if (attr ==  null) {
            System.out.println("AC is null.");
            return;
        }

        System.out.println("Serial number: " + attr.getSerialNumber());
        String issuerPrincipal = Arrays.stream(attr.getIssuer().getPrincipals()).map(p -> p.getName()).collect(Collectors.joining(","));
        System.out.println("Issuer: " + issuerPrincipal);
        System.out.println("Not before: " + attr.getNotBefore());
        System.out.println("Not after: " + attr.getNotAfter());
        System.out.println("Holder: " + attr.getHolder().getSerialNumber());

        for (X509Attribute x509Attribute : attr.getAttributes()) {
            System.out.println("Attribute: " + x509Attribute.getOID());
            for (ASN1Encodable encodable : x509Attribute.getValues()) {
                System.out.println("value: " + encodable.toString());
            }
        }
    }*/


    }
