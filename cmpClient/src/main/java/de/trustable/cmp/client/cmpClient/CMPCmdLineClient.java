package de.trustable.cmp.client.cmpClient;

import de.trustable.cmp.client.ProtectedMessageHandler;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.PEMWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Locale;

public class CMPCmdLineClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(CMPClientImpl.class);

    static CMPCmdLineClient cmpCmdLineClient = new CMPCmdLineClient();
    static CMPClientImpl client;


    public static void main(String[] args) {

        int ret = handleArgs(args);

        if( ret != 0) {
            System.exit(ret);
        }
    }

    public static int handleArgs(String[] args) {

        String mode = "Request";

        String plainSecret = null;
        String p12Secret = null;
        String p12Alias = null;
        String p12FileName = null;
        String p12ClientSecret = null;
        String p12ClientFileName = null;
        String caUrl = null;
        String alias = null;
        String certIssuer = null;
        String reason = "unspecified";
        String inFileName = "test.csr";
        String outFileName = "test.crt";
        String outForm = "PEM";
        boolean multipleMessages = true;
        boolean verbose = false;

        if( args.length == 0) {
            printHelp();
            return 1;
        }

        for( int i = 0; i < args.length; i++) {
            String arg = args[i];
            boolean nextArgPresent = (i + 1 < args.length);

            if( "-c".equals(arg)) {
                mode = "Request";
            } else if( "-r".equals(arg)) {
                mode = "Revoke";
            } else if( "-v".equals(arg)) {
                verbose = true;
            } else if( "-sm".equals(arg)) {
                multipleMessages = false;
            } else if( "-h".equals(arg)) {
                printHelp();
                return 0;
            } else {
                if( nextArgPresent ) {
                    i++;
                    String nArg = args[i];
                    if( "-u".equals(arg)) {
                        caUrl = nArg;
                    } else if( "-a".equals(arg)) {
                        alias = nArg;
                    } else if( "-ci".equals(arg)) {
                        certIssuer = nArg;
                    } else if( "-s".equals(arg)) {
                        plainSecret = nArg;
                    } else if( "-e".equals(arg)) {
                        reason = nArg;
                    } else if( "-i".equals(arg)) {
                        inFileName = nArg;
                    } else if( "-of".equals(arg)) {
                        outForm = nArg.toUpperCase(Locale.ROOT);
                    } else if( "-o".equals(arg)) {
                        outFileName = nArg;
                    } else if( "-ks".equals(arg)) {
                        p12Secret = nArg;
                    } else if( "-ka".equals(arg)) {
                        p12Alias = nArg;
                    } else if( "-kf".equals(arg)) {
                        p12FileName = nArg;
                    } else if( "-cs".equals(arg)) {
                        p12ClientSecret = nArg;
                    } else if( "-cf".equals(arg)) {
                        p12ClientFileName = nArg;
                    }

                }else {
                    System.err.println("option '" + arg + "' requires argument!");
                }
            }
        }

        if(caUrl == null) {
            System.err.println("'caUrl' must be provided! Exiting ...");
            return 1;
        }
        if(alias == null) {
            System.err.println("'alias' must be provided! Exiting ...");
            return 1;
        }

        if(!(outForm.equals("DER") || outForm.equals("PEM"))){
            System.err.println("unrecognized output format! Only PEM and DER are supported. Exiting ...");
            return 1;
        }

        try {

            File p12ClientFile = null;

            ProtectedMessageHandler signer;
            if( plainSecret != null && !plainSecret.isEmpty() ){
                signer = new DigestSigner(plainSecret);
            }else{

                if( p12FileName != null && !p12FileName.isEmpty() &&
                        p12Alias != null && !p12Alias.isEmpty() &&
                        p12Secret != null && !p12Secret.isEmpty() ) {

                    File p12File = new File(p12FileName);
                    if( !p12File.exists()) {
                        System.err.println("Keystore file '" + p12File + "' does not exist! Exiting ...");
                        return 1;
                    }
                    if( !p12File.canRead()) {
                        System.err.println("No read access to CSR file '" + p12File + "'! Exiting ...");
                        return 1;
                    }
                    KeyStore ks = KeyStore.getInstance("PKCS12");
                    ks.load(new FileInputStream(p12File), p12Secret.toCharArray());

                    signer = new KeystoreSigner(ks, p12Alias, p12Secret);

                }else{
                    System.err.println("Either HMAC Secret or Keystore/Alias/Password must be provided! Exiting ...");
                    return 1;
                }
            }
            FileInputStream fisClientStore = null;
            if( p12ClientFileName != null && !p12ClientFileName.isEmpty()){
                p12ClientFile = new File(p12ClientFileName);
                if( !p12ClientFile.exists()) {
                    System.err.println("Client keystore file '" + p12ClientFile + "' does not exist! Exiting ...");
                    return 1;
                }
                if( !p12ClientFile.canRead()) {
                    System.err.println("No read access to CSR file '" + p12ClientFile + "'! Exiting ...");
                    return 1;
                }
                fisClientStore = new FileInputStream(p12ClientFile);
            }

            CMPClientConfig cmpClientConfig = new CMPClientConfig();
            cmpClientConfig.setMessageHandler(signer);
            cmpClientConfig.setRemoteTargetHandler(new SimpleRemoteTargetHandler());
            cmpClientConfig.setCaUrl(caUrl);
            cmpClientConfig.setCmpAlias(alias);

            if( certIssuer != null){
                cmpClientConfig.setIssuerName(new X500Name(certIssuer));
            }
            cmpClientConfig.setP12ClientStore(fisClientStore);
            cmpClientConfig.setP12ClientSecret(p12ClientSecret);
            cmpClientConfig.setMultipleMessages(multipleMessages);
            cmpClientConfig.setVerbose(verbose);

            client = new CMPClientImpl(cmpClientConfig);

            if( "Request".equals(mode)) {

                System.out.println("Requesting certificate from csr file '" + inFileName + "' ...");

                File inFile = new File(inFileName);
                if( !inFile.exists()) {
                    System.err.println("CSR file '" + inFile + "' does not exist! Exiting ...");
                    return 1;
                }
                if( !inFile.canRead()) {
                    System.err.println("No read access to CSR file '" + inFile + "'! Exiting ...");
                    return 1;
                }

                File outFile = new File(outFileName);
                if( outFile.exists()) {
                    System.err.println("Certificate file '" + outFile + "' already exist! Exiting ...");
                    return 1;
                }

                cmpCmdLineClient.signCertificateRequest(inFile, outFile, outForm);
            } else if( "Revoke".equals(mode)) {

                System.out.println("Revoking certificate from file '" + inFileName + "' ...");

                File inFile = new File(inFileName);
                if( !inFile.exists()) {
                    System.err.println("Certificate file '" + inFileName + "' does not exist! Exiting ...");
                    return 1;
                }
                if( !inFile.canRead()) {
                    System.err.println("No read access to certificate file '" + inFileName + "'! Exiting ...");
                    return 1;
                }

                client.revokeCertificate(inFile, reason);

            } else {
                System.err.println("Either an option '-c' (certificate creation) or '-r' (revocation)!");
                printHelp();
                return 1;
            }
        } catch(GeneralSecurityException | IOException ex) {
            System.err.println(" WARN: problem occurred " + ex.getMessage());
            if(verbose) {
                ex.printStackTrace();
            }
        }
        return 0;
    }


    private static void printHelp() {
        System.out.println("\nSimple CMP Client\n");

        System.out.println("Options:\n");
        System.out.println("-c\t\tRequest a certificate");
        System.out.println("-r\t\tRevoke a certificate");
        System.out.println("-h\t\tPrint help");

        System.out.println("\nArguments:\n");
        System.out.println("-u caURL\tCA URL (required)");
        System.out.println("-a alias\tAlias configuration (required)");
        System.out.println("-s secret\tCMP secret for CMP message authentication (option 1)");
        System.out.println("-kf filename\tKeystore file name for CMP message authentication, PKCS12 type expected (option 2)");
        System.out.println("-ks secret\tKeystore secret (option 2)");
        System.out.println("-ka alias\tKeystore alias (option 2)");
        System.out.println("-cf filename\tKeystore file name for HTTPS client authentication, PKCS12 type expected");
        System.out.println("-cs secret\tKeystore secret for HTTPS client authentication. An alias is not required for this store");
        System.out.println("-sm\tsend single PKIMessage object, only");
        System.out.println("-e reason\trevocation reason (required for revocation), valid values are");
        System.out.println("\t\tkeyCompromise");
        System.out.println("\t\tcACompromise");
        System.out.println("\t\taffiliationChanged");
        System.out.println("\t\tsuperseded");
        System.out.println("\t\tcessationOfOperation");
        System.out.println("\t\tprivilegeWithdrawn");
        System.out.println("\t\taACompromise");
        System.out.println("\t\tcertificateHold");
        System.out.println("\t\tremoveFromCRL");
        System.out.println("\t\tunspecified\n");

        System.out.println("-i input\tCSR (required for request) / certificate file (required for revocation)");
        System.out.println("-o output\tCertificate file");
        System.out.println("-of format\tselect PEM or DER format");

        System.out.println("-v verbose\tenable verbose log output");

        System.out.println("\nSample use of keytool to create a csr and submit a request:");
        System.out.println("keytool -genkeypair -keyalg RSA -keysize 2048 -keystore test.p12 -storepass s3cr3t -alias keyAlias -storetype pkcs12 -dname \"C=DE, OU=dev, O=trustable, CN=test.trustable.de\" " );
        System.out.println("keytool -certreq -keystore test.p12 -storepass s3cr3t -alias keyAlias -ext \"SAN=dns:www.test.trustable.de\" -file test.csr" );
        System.out.println("java -jar cmpClient-1.3.0-jar-with-dependencies.jar -c -u http://{yourServer}/ejbca/publicweb/cmp -a {yourCMPAlias} -s {yourPassword} -i test.csr -o test.crt" );

        System.out.println("\nRevocation sample (DER and PEM certificate format supported):");
        System.out.println("java -jar cmpClient-1.2.0-jar-with-dependencies.jar -r -u http://{yourServer}/ejbca/publicweb/cmp -a {yourCMPAlias} -s {yourPassword} -i test.crt -e superseded" );

        System.out.println("\ncode available at https://github.com/kuehne-trustable-de/cmpClient");

    }


    public void signCertificateRequest(final File csrFile, final File certFile, final String outForm)
            throws GeneralSecurityException, IOException {

        InputStream isCSR = new FileInputStream(csrFile);

        X509Certificate cert = client.signCertificateRequest(isCSR);

        if("DER".equals(outForm)) {
            try(FileOutputStream osCert = new FileOutputStream(certFile)) {
                osCert.write(cert.getEncoded());
            }
        }else{
            try(PEMWriter pemWriter = new PEMWriter(new FileWriter(certFile))){
                pemWriter.writeObject(cert);
            }
        }

        if( cert.getSubjectDN() != null && cert.getSubjectDN().getName() != null) {
            LOGGER.info("creation of certificate with subject '" + cert.getSubjectDN().getName() + "' written to file '" + certFile.getName() +"' (in " + outForm + " format)" );
        }else{
            LOGGER.info("creation of certificate written to file '" + certFile.getName() +"'");
        }

    }

}
