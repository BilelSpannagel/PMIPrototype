import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

/**
 * Class name: ${CLASS_NAME}
 * Created by kevin on 09.05.17.
 */
public class ConsoleOptions {

    private final Options options;

    public  ConsoleOptions() {
        options = new Options();

        Option quit = new Option("q", "quit", false, "Quit the program.");
        options.addOption(quit);

        Option help = new Option("h", "help", false, "Shows the help page.");
        options.addOption(help);

        Option request = new Option("r", "request", false, "Creates a certificate request.");
        options.addOption(request);

        Option poll = new Option("p", "poll", false, "Tries to poll a certificate by transaction id and subject.");
        options.addOption(poll);

        Option get = new Option("g", "get", false, "Tries to get a certificate by serial number.");
        options.addOption(get);

        Option validate = new Option("v", "validate", false, "Validates a given certificate.");
        options.addOption(validate);

        Option revoke = new Option("k", "revoke", false, "Revokes an enrolled certificate by serial number.");
        options.addOption(revoke);

        Option revokeRequest = new Option("q", "revokerequest", false, "Revokes a certificate request.");
        options.addOption(revokeRequest);

        Option createACRequest = new Option("a", "requestac", false, "Creates a attribute certificate request.");
        options.addOption(createACRequest);
        Option getAC = new Option("ga", "get", false, "Tries to get an Attribute Certificate by serial number.");
        options.addOption(getAC);
        Option revokeAC = new Option("rv", "revoke", false, "Tries to revoke an Attribute Certificate by serial number.");
        options.addOption(revokeAC);
        Option validatepkcac = new Option("va", "validatepkcac", false, "Validates the AC and PKC");
        options.addOption(validatepkcac);

    }

    public Options getOptions() {
        return options;
    }

}
