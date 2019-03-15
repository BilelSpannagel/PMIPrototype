import org.apache.commons.cli.*;

import java.util.Scanner;
import com.mysql.jdbc.Driver;
/**
 * Class name: ${CLASS_NAME}
 * Created by kevin on 09.05.17.
 */
public class Main {

    public static void main(String[] args) throws ParseException {
        CertificateManagement cm = new CertificateManagement();

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        Options options = new ConsoleOptions().getOptions();
        Scanner scanner = new Scanner(System.in);

        System.out.println("PMIClient started...");
        while (true) {
            String test = scanner.nextLine();
            String[] input = test.split(" ");
            try {
                CommandLine cmd = parser.parse(options, input, true);

                if (cmd.hasOption("q")) {
                    scanner.close();
                    System.out.println("Program quit.");
                    System.exit(0);
                    return;
                } else if (cmd.hasOption("r")) {
                    System.out.print("Enter subject:");
                    String subject = scanner.nextLine();
                    System.out.print("Enter public key file name:");
                    String pubFileName = scanner.nextLine();
                    System.out.print("Enter private key file name:");
                    String privFileName = scanner.nextLine();
                    cm.createCertificateRequest(subject, pubFileName, privFileName);
                } else if (cmd.hasOption("h")) {
                    formatter.printHelp("PMIClient", options);
                } else if (cmd.hasOption("p")) {
                    System.out.print("Enter request string:");
                    String requestString = scanner.nextLine();
                    cm.pollCertificate(requestString);
                } else if (cmd.hasOption("g")) {
                    System.out.print("Enter serial number:");
                    String serialNumber = scanner.nextLine();
                    cm.getCertificate(serialNumber);
                } else if (cmd.hasOption("v")) {
                    System.out.print("Enter certificate file name:");
                    String certificateFileName = scanner.nextLine();
                    cm.validateCertificate(certificateFileName);
                } else if (cmd.hasOption("k")) {
                    // TODO: implement revoke certificate
                    cm.revokeCertificate(null);
                } else if (cmd.hasOption("q")) {
                    // TODO: implement revoke certificate request
                    cm.revokeCertificateRequest(null);
                } else if (cmd.hasOption("a")) {
                    System.out.println("Enter certificate file name:");
                    String certificateFilename = scanner.nextLine();
                    System.out.println("Enter requested attribute:");
                    String attribute = scanner.nextLine();
                    cm.createAttributeCertificateRequest(certificateFilename, attribute);
                }else if (cmd.hasOption("ga")){
                    System.out.println("Enter the serial number from the AC:");
                    String serialnumber = scanner.nextLine();
                    cm.getAttributeCertificate(serialnumber);
                }else if (cmd.hasOption("rv")){
                    System.out.println("Enter the serial number from the AC:");
                    String serialnumber = scanner.nextLine();
                    cm.revokeAttributCertificate(serialnumber);
                }else if (cmd.hasOption("va")){
                    System.out.println("Enter certificate file name:");
                    String certificateFilename = scanner.nextLine();
                    System.out.println("Enter Base64-AttributeCertificate Value:");
                    String base64ac = scanner.nextLine();
                    cm.requestPkcAc(certificateFilename, base64ac);
                }

            } catch (Exception e) {
                e.printStackTrace();
                formatter.printHelp("PMIClient", options);
            }
        }
    }
}
