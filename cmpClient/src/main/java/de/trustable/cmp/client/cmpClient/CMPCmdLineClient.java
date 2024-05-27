package de.trustable.cmp.client.cmpClient;

import de.trustable.cmp.client.ProtectedMessageHandler;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import java.security.Security;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.LMSHSSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Locale;

public class CMPCmdLineClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(CMPCmdLineClient.class);

    static CMPCmdLineClient cmpCmdLineClient = new CMPCmdLineClient();
    static CMPClientImpl client;


    public static void main(String[] args) {

        Security.addProvider(new BouncyCastlePQCProvider());

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
        String msgContentType = "application/pkixcmp";
        String alias = null;
        String certIssuer = null;
        String reason = "unspecified";
        String inFileName = "test.csr";
        String outFileName = "test.crt";
        String outForm = "PEM";

        String buildAlgo = "RSA";
        String buildAlgoLen = null;
        String buildAlgoAlt = null;
        String buildAlgoLenAlt = null;

        boolean multipleMessages = true;
        boolean implicitConfirm = true;
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
            } else if( "-b".equals(arg)) {
                mode = "Build";
            } else if( "-v".equals(arg)) {
                verbose = true;
            } else if( "-sm".equals(arg)) {
                multipleMessages = false;
            } else if( "-ic".equals(arg)) {
                implicitConfirm = true;
            } else if( "-h".equals(arg)) {
                printHelp();
                return 0;
            } else {
                if( nextArgPresent ) {
                    i++;
                    String nArg = args[i];
                    if( "-u".equals(arg)) {
                        caUrl = nArg;
                    } else if( "-ct".equals(arg)) {
                        msgContentType = nArg;
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
                    } else if( "-balgo".equalsIgnoreCase(arg)) {
                        buildAlgo = nArg;
                    } else if( "-balgolen".equalsIgnoreCase(arg)) {
                        buildAlgoLen = nArg;
                    } else if( "-balgoalt".equalsIgnoreCase(arg)) {
                        buildAlgoAlt = nArg;
                    } else if( "-balgolenalt".equalsIgnoreCase(arg)) {
                        buildAlgoLenAlt = nArg;
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

            File p12ClientFile;

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
            cmpClientConfig.setImplicitConfirm(implicitConfirm);
            cmpClientConfig.setMsgContentType(msgContentType);

            if( certIssuer != null){
                cmpClientConfig.setIssuerName(new X500Name(certIssuer));
            }

            if( plainSecret != null && !plainSecret.isEmpty() ) {
                // identification by plain secret
            }else{
                KeyStore keyStore = KeyStore.getInstance("PKCS12");
                keyStore.load(fisClientStore, p12ClientSecret.toCharArray());
                fisClientStore.close();

                cmpClientConfig.setP12ClientStore(keyStore);
                cmpClientConfig.setP12ClientSecret(p12ClientSecret);
            }

            cmpClientConfig.setMultipleMessages(multipleMessages);
            cmpClientConfig.setVerbose(verbose);

            client = new CMPClientImpl(cmpClientConfig);

            if ("Build".equals(mode)) {

                KeyPair keyPairPrimary = createKeyPair(buildAlgo, buildAlgoLen);
                KeyPair keyPairAlt = null;
                SubjectPublicKeyInfo subjectPublicKeyInfoAlt = null;
                if( buildAlgoAlt != null){
                    keyPairAlt = createKeyPair(buildAlgoAlt, buildAlgoLenAlt);
                    subjectPublicKeyInfoAlt = SubjectPublicKeyInfo.getInstance(keyPairAlt.getPublic().getEncoded());
                }

                PKCS10CertificationRequest pkcs10CertificationRequest = PKCS10Generator.getCsr(
                    new X500Name("CN=PQC Hybrid Test"),
                    keyPairPrimary.getPublic(),
                    keyPairPrimary.getPrivate(),
                    subjectPublicKeyInfoAlt,
                    null);

                X509Certificate cert = client.signCertificateRequest(pkcs10CertificationRequest).createdCertificate;

                System.out.println("certficate created : " + cert);

                FileWriter fileWriterCert = new FileWriter(outFileName + ".pem");
                try (JcaPEMWriter pemWriterCert = new JcaPEMWriter(fileWriterCert)) {
                    pemWriterCert.writeObject(cert);
                }
                fileWriterCert.close();

                FileWriter fileWriterKey = new FileWriter(outFileName + ".key." + buildAlgo.toLowerCase(Locale.ROOT)+ ".pem");
                try (JcaPEMWriter pemWriterCert = new JcaPEMWriter(fileWriterKey)) {
                    pemWriterCert.writeObject(keyPairPrimary.getPrivate());
                }
                fileWriterKey.close();

                if( buildAlgoAlt != null) {
                    fileWriterKey = new FileWriter(outFileName + ".key." + buildAlgoAlt.toLowerCase(Locale.ROOT)+ ".pem");
                    try (JcaPEMWriter pemWriterCert = new JcaPEMWriter(fileWriterKey)) {
                        pemWriterCert.writeObject(keyPairAlt.getPrivate());
                    }
                    fileWriterKey.close();
                }

            } else if ("Request".equals(mode)) {

                System.out.println("Requesting certificate from csr file '" + inFileName + "' ...");

                File inFile = new File(inFileName);
                if (!inFile.exists()) {
                    System.err.println("CSR file '" + inFile + "' does not exist! Exiting ...");
                    return 1;
                }
                if (!inFile.canRead()) {
                    System.err.println("No read access to CSR file '" + inFile + "'! Exiting ...");
                    return 1;
                }

                File outFile = new File(outFileName);
                if (outFile.exists()) {
                    System.err.println("Certificate file '" + outFile + "' already exist! Exiting ...");
                    return 1;
                }
                cmpCmdLineClient.signCertificateRequest(inFile, outFile, outForm);

            } else if ("Revoke".equals(mode)) {

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


    private static KeyPair createKeyPair(String algorithmName, String keyLength)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        LOGGER.info("building '{}' using provider '{}' ", algorithmName);

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithmName);

        if ("RSA".equalsIgnoreCase(algorithmName)) {
            int rsaLength = 2048;
            if( keyLength != null ){
                try {
                    rsaLength = Integer.parseInt(keyLength);
                } catch( NumberFormatException nfe){
                    System.err.println("key length argument not parseable, using 2048.");
                }
            }
            kpGen.initialize(rsaLength);
        } else if (algorithmName.toUpperCase(Locale.ROOT).startsWith("DILITHIUM")){
            // nothing to do
        }

        return kpGen.generateKeyPair();
    }

    private static void printHelp() {
        System.out.println("\nSimple CMP Client\n");

        System.out.println("Options:\n");
        System.out.println("-c\t\tRequest a certificate");
        System.out.println("-r\t\tRevoke a certificate");
        System.out.println("-h\t\tPrint help");

        System.out.println("\nArguments:\n");
        System.out.println("-u caURL\tCA URL (required)");
        System.out.println("-ct contentType\tMeassage comtent type of the CMP message (default 'application/pkixcmp')");
        System.out.println("-a alias\tAlias configuration (required)");
        System.out.println("-s secret\tCMP secret for CMP message authentication (option 1)");
        System.out.println("-kf filename\tKeystore file name for CMP message authentication, PKCS12 type expected (option 2)");
        System.out.println("-ks secret\tKeystore secret (option 2)");
        System.out.println("-ka alias\tKeystore alias (option 2)");
        System.out.println("-ci issuer\tX500 name of the issuer.");
        System.out.println("-cf filename\tKeystore file name for HTTPS client authentication, PKCS12 type expected");
        System.out.println("-cs secret\tKeystore secret for HTTPS client authentication. An alias is not required for this store");
        System.out.println("-sm\tsend single PKIMessage object, only (default 'false'')");
        System.out.println("-ic\t'implicitConfirm' flag of the request (default 'true')");

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

    private void getCAInfo() throws GeneralSecurityException {

        GenMsgContent genMsgContent = client.getGeneralMessageRequest();

    }

    public void signCertificateRequest(final File csrFile, final File certFile, final String outForm)
            throws GeneralSecurityException, IOException {

        InputStream isCSR = new FileInputStream(csrFile);

        X509Certificate cert = client.signCertificateRequest(isCSR).createdCertificate;

        if("DER".equals(outForm)) {
            try(FileOutputStream osCert = new FileOutputStream(certFile)) {
                osCert.write(cert.getEncoded());
            }
        }else{
            try(JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(certFile))){
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
