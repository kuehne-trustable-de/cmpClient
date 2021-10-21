package de.trustable.cmp.client.cmpClient;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevRepContent;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.Base64;


/**
 * Simple CMP Client to request or revoke a certificate using the CMP protocol, based on Bouncy Castle
 *
 */
public class CMPClient {
	
    SecureRandom secRandom = new SecureRandom();

	private String plainSecret = "foo123";
	private String caUrl = "http://...,"; 
	private String alias = "test";
	boolean verbose = false;


	private CMPClient() {
        java.security.Security.addProvider( new BouncyCastleProvider() );
	}
	
	public CMPClient(String caUrl, String alias, String plainSecret, boolean verbose) {
		this();
		
		this.plainSecret = plainSecret;
		this.caUrl = caUrl; 
		this.alias = alias;
		this.verbose = verbose;
	}


	public static void main(String[] args) {

		int ret = handleArgs(args);

		if( ret != 0) {
			System.exit(ret);
		}

	}
	
	public static int handleArgs(String[] args) {
	
		String mode = "Request";

		String plainSecret = null;
		String caUrl = null; 
		String alias = null;
		String reason = "unspecified";
		String csrFile = "test.csr";
		String certFile = "test.crt";
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
					} else if( "-s".equals(arg)) {
						plainSecret = nArg;
					} else if( "-e".equals(arg)) {
						reason = nArg;
					} else if( "-i".equals(arg)) {
						csrFile = nArg;
					} else if( "-o".equals(arg)) {
						certFile = nArg;
					}
					
				}else {
					System.err.println("option '" + arg + "' requires argument!");
				}
			}
		}

		if(plainSecret == null) {
			System.err.println("'secret' must be provided! Exiting ...");
			return 1;
		}
		if(caUrl == null) {
			System.err.println("'caUrl' must be provided! Exiting ...");
			return 1;
		}
		if(alias == null) {
			System.err.println("'alias' must be provided! Exiting ...");
			return 1;
		}

		try {
			CMPClient client = new CMPClient( caUrl, alias, plainSecret, verbose);
			if( "Request".equals(mode)) {

				System.out.println("Requesting certificate from csr file '" + csrFile + "' ...");

				File inFile = new File(csrFile);
				if( !inFile.exists()) {
					System.err.println("CSR file '" + csrFile + "' does not exist! Exiting ...");
					return 1;
				}
				if( !inFile.canRead()) {
					System.err.println("No read access to CSR file '" + csrFile + "'! Exiting ...");
					return 1;
				}
				
				File outFile = new File(certFile);
				if( outFile.exists()) {
					System.err.println("Certificate file '" + certFile + "' already exist! Exiting ...");
					return 1;
				}
				
				client.signCertificateRequest(inFile, outFile);
			} else if( "Revoke".equals(mode)) {

				System.out.println("Revoking certificate from file '" + certFile + "' ...");

				File inFile = new File(certFile);
				if( !inFile.exists()) {
					System.err.println("Certificate file '" + certFile + "' does not exist! Exiting ...");
					return 1;
				}
				if( !inFile.canRead()) {
					System.err.println("No read access to certificate file '" + certFile + "'! Exiting ...");
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
		System.out.println("-s secret\tCMP access secret (required)");
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

		System.out.println("-v verbose\tenable verbose log output");

		System.out.println("\nSample use of keytool to create a csr and submit a request:");
		System.out.println("keytool -genkeypair -keyalg RSA -keysize 2048 -keystore test.p12 -storepass s3cr3t -alias keyAlias -storetype pkcs12 -dname \"C=DE, OU=dev, O=trustable, CN=test.trustable.de\" " );
		System.out.println("keytool -certreq -keystore test.p12 -storepass s3cr3t -alias keyAlias -ext \"SAN=dns:www.test.trustable.de\" -file test.csr" );
		System.out.println("java -jar cmpClient-1.2.0-jar-with-dependencies.jar -c -u http://{yourServer}/ejbca/publicweb/cmp -a {yourCMPAlias} -s {yourPassword} -i test.csr -o test.crt" );

		System.out.println("\nRevocation sample:");
		System.out.println("java -jar cmpClient-1.2.0-jar-with-dependencies.jar -r -u http://{yourServer}/ejbca/publicweb/cmp -a {yourCMPAlias} -s {yourPassword} -o test.crt -e superseded" );

	}

	public void signCertificateRequest(final File csrFile, final File certFile)
			throws GeneralSecurityException, IOException {
		
		InputStream isCSR = new FileInputStream(csrFile);
		
		X509Certificate cert = signCertificateRequest(isCSR);

		FileOutputStream osCert = new FileOutputStream(certFile);
		osCert.write(cert.getEncoded());
		osCert.close();

		if( cert.getSubjectDN() != null && cert.getSubjectDN().getName() != null) {
			log("creation of certificate with subject '" + cert.getSubjectDN().getName() + "' written to file '" + certFile.getName() +"'");
		}else{
			log("creation of certificate written to file '" + certFile.getName() +"'");
		}

	}
	
	public X509Certificate signCertificateRequest(final InputStream isCSR)
			throws GeneralSecurityException {

		long certReqId = secRandom.nextLong();

		try {

			// build a CMP request from the CSR
			PKIMessage pkiRequest = buildCertRequest(certReqId, isCSR, plainSecret);

			byte[] requestBytes = pkiRequest.getEncoded();

			trace("requestBytes : " + java.util.Base64.getEncoder().encodeToString(requestBytes));
			trace("cmp client calls url '"+caUrl+"' with alias '"+alias+"'");

			// send and receive ..
			byte[] responseBytes = sendHttpReq(caUrl + "/" + alias, requestBytes);

			if (responseBytes == null) {
				throw new GeneralSecurityException("remote connector returned 'null'");
			}

			trace("responseBytes : " + java.util.Base64.getEncoder().encodeToString(responseBytes));

			// extract the certificate
			return readCertResponse(responseBytes, pkiRequest);

		} catch (CRMFException e) {
			log("CMS format problem", e);
			throw new GeneralSecurityException(e.getMessage());
		} catch (CMPException e) {
			log("CMP problem", e);
			throw new GeneralSecurityException(e.getMessage());
		} catch (IOException e) {
			log("IO / encoding problem", e);
			throw new GeneralSecurityException(e.getMessage());
		}
	}

	/**
	 * revoke a given certificate
	 * @param certFile the File handle of the input certificate 
	 * @param reason the reason as a string
	 * @throws GeneralSecurityException something cryptographic went wrong
	 * @throws IOException file access failed somehow
	 */
	public void revokeCertificate(final File certFile, final String reason) throws GeneralSecurityException, IOException {

		InputStream isCert = new FileInputStream(certFile);
		try {

			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			X509Certificate x509Cert = (X509Certificate) certificateFactory.generateCertificate(isCert);

			CRLReason crlReason = crlReasonFromString(reason);

			revokeCertificate(JcaX500NameUtil.getIssuer(x509Cert), JcaX500NameUtil.getSubject(x509Cert),
					x509Cert.getSerialNumber(), crlReason);

			log("revocation of certificate '"+x509Cert.getSubjectDN().getName()+"' with reason '"+reason+"' succeeded!");

		} finally {
			isCert.close();
		}
	}

	/**
	 * revoke a certificate identified by issuer, subject and serial
	 * @param issuerDN The X500Name of the issuer
	 * @param subjectDN The X500Name of the subject
	 * @param serial the serial
	 * @param crlReason reason the reason as a BC enum 
	 * @throws GeneralSecurityException something cryptographic went wrong
	 */
	public void revokeCertificate(final X500Name issuerDN, final X500Name subjectDN, final BigInteger serial,
			final CRLReason crlReason)
			throws GeneralSecurityException {

		long certRevId = new Random().nextLong();

		try {

			// build a CMP request from the revocation infos
			byte[] revocationRequestBytes = buildRevocationRequest(certRevId, issuerDN, subjectDN, serial, crlReason);

			// send and receive ..
			trace("revocation requestBytes : " + java.util.Base64.getEncoder().encodeToString(revocationRequestBytes));
			byte[] responseBytes = sendHttpReq(caUrl + "/" + alias, revocationRequestBytes);
			trace("revocation responseBytes : " + java.util.Base64.getEncoder().encodeToString(responseBytes));

			// handle the response
			readRevResponse(responseBytes);

		} catch (CRMFException e) {
			log("CMS format problem", e);
			throw new GeneralSecurityException(e.getMessage());
		} catch (CMPException e) {
			log("CMP problem", e);
			throw new GeneralSecurityException(e.getMessage());
		} catch (IOException e) {
			log("IO / encoding problem", e);
			throw new GeneralSecurityException(e.getMessage());
		}
	}

	/**
	 * build the CMP request message
	 * @param certReqId the handle id for the request
	 * @param isCSR input stream of the CSR file
	 * @param hmacSecret the secret for the message authentication
	 * @return the CMP request message
	 * @throws GeneralSecurityException something cryptographic went wrong
	 */
	public PKIMessage buildCertRequest(long certReqId, final InputStream isCSR, final String hmacSecret)
			throws GeneralSecurityException {

		PKCS10CertificationRequest p10Req = convertPemToPKCS10CertificationRequest(isCSR);

		X500Name subjectDN = p10Req.getSubject();
		trace("subjectDN : " + subjectDN.toString());

		Collection<Extension> certExtList = new ArrayList<>();

		// copy CSR attributes to Extension list
		for(Attribute attribute: p10Req.getAttributes()){
			for(ASN1Encodable asn1Encodable: attribute.getAttributeValues()){
				if( asn1Encodable != null){
					Extensions extensions = Extensions.getInstance(asn1Encodable);
					for(ASN1ObjectIdentifier oid: extensions.getExtensionOIDs()){
						trace("copying oid '"+oid.toString()+"' from csr to PKIMessage");
						certExtList.add(extensions.getExtension(oid));
					}
				}
			}
		}

		final SubjectPublicKeyInfo keyInfo = p10Req.getSubjectPublicKeyInfo();

		try {
			if( !p10Req.isSignatureValid(new JcaContentVerifierProviderBuilder().build(keyInfo))){
				throw new GeneralSecurityException("CSR signature validation failed");
			}
		} catch (PKCSException | OperatorCreationException e) {
			throw new GeneralSecurityException(e);
		}

		return buildCertRequest(certReqId, p10Req.getSubject(), certExtList, keyInfo, hmacSecret);

	}


	/**
	 * 
	 * @param certReqId the handle id for the request
	 * @param subjectDN The X500Name of the subject
	 * @param certExtList a collection o extensions, eg SANS
	 * @param keyInfo the identification data of the key
	 * @param hmacSecret the secret for the message authentication
	 * @return the CMP request message
	 * @throws GeneralSecurityException something cryptographic went wrong
	 */
	public PKIMessage buildCertRequest(long certReqId, final X500Name subjectDN,
			final Collection<Extension> certExtList, final SubjectPublicKeyInfo keyInfo, final String hmacSecret)
			throws GeneralSecurityException {

		CertificateRequestMessageBuilder msgbuilder = new CertificateRequestMessageBuilder(
				BigInteger.valueOf(certReqId));

		X500Name issuerDN = X500Name.getInstance(new X500Name("CN=AdminCA1").toASN1Primitive());

		msgbuilder.setSubject(subjectDN);

		// propose an issuer ???
		msgbuilder.setIssuer(issuerDN);

		try {
			for (Extension ext : certExtList) {
				trace("Csr Extension : " + ext.getExtnId().getId() + " -> " + ext.getExtnValue());
				boolean critical = ext.isCritical();
				msgbuilder.addExtension(ext.getExtnId(), critical, ext.getParsedValue());
			}

			msgbuilder.setPublicKey(keyInfo);
			GeneralName sender = new GeneralName(subjectDN);
			msgbuilder.setAuthInfoSender(sender);

			// RAVerified POP
			// I am a  client, I do trust my master!
			msgbuilder.setProofOfPossessionRaVerified();

			CertificateRequestMessage msg = msgbuilder.build();
			trace("CertTemplate : " + msg.getCertTemplate());

			ProtectedPKIMessageBuilder pbuilder = getPKIBuilder(issuerDN, subjectDN);

			CertReqMessages msgs = new CertReqMessages(msg.toASN1Structure());
			PKIBody pkibody = new PKIBody(PKIBody.TYPE_INIT_REQ, msgs);
			pbuilder.setBody(pkibody);

			MacCalculator macCalculator = getMacCalculator(hmacSecret);
			ProtectedPKIMessage message = pbuilder.build(macCalculator);

			return message.toASN1Structure();

		} catch (CRMFException | CMPException | IOException crmfe) {
			log("Exception occured processing extensions", crmfe);
			throw new GeneralSecurityException(crmfe.getMessage());
		}
	}


	/**
	 * read the response certificate from the CMP response
	 * @param responseBytes the unparsed response bytes
	 * @param pkiMessageReq the coresponding request
	 * @return the created certificate
	 * @throws IOException io interaction failed somehow
	 * @throws CRMFException certificate request related problem
	 * @throws CMPException CMP related problem
	 * @throws GeneralSecurityException something cryptographic went wrong
	 */
	public X509Certificate readCertResponse(final byte[] responseBytes,
			final PKIMessage pkiMessageReq)
			throws IOException, CRMFException, CMPException, GeneralSecurityException {


		// validate protected messages
		buildPKIMessage(responseBytes);

		final ASN1Primitive derObject = getDERObject(responseBytes);
		final PKIMessage pkiMessage = PKIMessage.getInstance(derObject);
		if (pkiMessage == null) {
			throw new GeneralSecurityException("No CMP message could be parsed from received Der object.");
		}

		PKIHeader pkiHeaderReq = pkiMessageReq.getHeader();
		PKIHeader pkiHeaderResp = pkiMessage.getHeader();

		if (!pkiHeaderReq.getSenderNonce().equals(pkiHeaderResp.getRecipNonce())) {
			ASN1OctetString asn1Oct = pkiHeaderResp.getRecipNonce();
			if (asn1Oct == null) {
				log("Recip nonce == null");
			} else {
				log("sender nonce differ from recepient nonce "
						+ java.util.Base64.getEncoder().encodeToString(pkiHeaderReq.getSenderNonce().getOctets())
						+ " != " + java.util.Base64.getEncoder().encodeToString(asn1Oct.getOctets()));
			}
			throw new GeneralSecurityException("Sender / Recip nonce mismatch");
		}
		/*
		 * if( !pkiHeaderReq.getSenderKID().equals(pkiHeaderResp.getRecipKID())){
		 * ASN1OctetString asn1Oct = pkiHeaderResp.getRecipKID(); if( asn1Oct == null ){
		 * LOGGER.info("Recip kid  == null"); }else{ LOGGER.info("sender kid " +
		 * Base64.encodeBase64String( pkiHeaderReq.getSenderKID().getOctets() ) +
		 * " != recip kid " + Base64.encodeBase64String( asn1Oct.getOctets() )); } //
		 * throw new GeneralSecurityException( "Sender / Recip Key Id mismatch");
		 * 
		 * asn1Oct = pkiHeaderResp.getSenderKID(); if( asn1Oct == null ){
		 * LOGGER.info("sender kid  == null"); }else{ LOGGER.info("sender kid " +
		 * Base64.encodeBase64String( pkiHeaderReq.getSenderKID().getOctets() ) + " != "
		 * + Base64.encodeBase64String( asn1Oct.getOctets() )); } }
		 */

		if (!pkiHeaderReq.getTransactionID().equals(pkiHeaderResp.getTransactionID())) {
			ASN1OctetString asn1Oct = pkiHeaderResp.getTransactionID();
			if (asn1Oct == null) {
				log("transaction id == null");
			} else {
				log("transaction id differ between request and response: "
						+ java.util.Base64.getEncoder().encodeToString(pkiHeaderReq.getTransactionID().getOctets())
						+ " != " + java.util.Base64.getEncoder().encodeToString(asn1Oct.getOctets()));
			}
			throw new GeneralSecurityException("Sender / Recip Transaction Id mismatch");
		}

		final PKIBody body = pkiMessage.getBody();

		int tagno = body.getType();

		if (tagno == PKIBody.TYPE_ERROR) {
			handleCMPError(body);

		} else if (tagno == PKIBody.TYPE_CERT_REP || tagno == PKIBody.TYPE_INIT_REP) {
			// certificate successfully generated
			CertRepMessage certRepMessage = CertRepMessage.getInstance(body.getContent());

			try {
				// CMPCertificate[] cmpCertArr = certRepMessage.getCaPubs();
				CMPCertificate[] cmpCertArr = pkiMessage.getExtraCerts();
				log("CMP Response body contains " + cmpCertArr.length + " extra certificates");
				for (int i = 0; i < cmpCertArr.length; i++) {
					CMPCertificate cmpCert = cmpCertArr[i];
					trace("Added CA '" + cmpCert.getX509v3PKCert().getSubject() + "' from CMP Response body");
					// store if required ...
				}
			} catch (NullPointerException npe) { // NOSONAR
				// just ignore
			}

			CertResponse[] respArr = certRepMessage.getResponse();
			if (respArr == null || (respArr.length == 0)) {
				throw new GeneralSecurityException("No CMP response found.");
			}

			trace("CMP Response body contains " + respArr.length + " elements");

			for (int i = 0; i < respArr.length; i++) {

				if (respArr[i] == null) {
					throw new GeneralSecurityException("CMP response element #"+i+" of "+ respArr.length+" returns no content.");
				}

				BigInteger status = BigInteger.ZERO;
				String statusText = "";

				PKIStatusInfo pkiStatusInfo = respArr[i].getStatus();
				if (pkiStatusInfo != null) {
					PKIFreeText freeText = pkiStatusInfo.getStatusString();
					if (freeText != null) {
						for (int j = 0; j < freeText.size(); j++) {
							statusText = freeText.getStringAt(j) + "\n";
						}
					}
				}

				if ((respArr[i].getCertifiedKeyPair() == null)
						|| (respArr[i].getCertifiedKeyPair().getCertOrEncCert() == null)) {
					throw new GeneralSecurityException(
							"CMP response contains no certificate, status :" + status + "\n" + statusText);
				}

				CMPCertificate cmpCert = respArr[i].getCertifiedKeyPair().getCertOrEncCert().getCertificate();
				if (cmpCert != null) {
					org.bouncycastle.asn1.x509.Certificate cmpCertificate = cmpCert.getX509v3PKCert();
					if (cmpCertificate != null) {

						trace("#" + i + ": " + cmpCertificate);

						final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");

						/*
						 * version returning just the end entity ...
						 */
						final Collection<? extends java.security.cert.Certificate> certificateChain = certificateFactory
								.generateCertificates(new ByteArrayInputStream(cmpCertificate.getEncoded()));

						X509Certificate[] certArray = certificateChain.toArray(new X509Certificate[0]);

						X509Certificate cert = certArray[0];
						trace("#" + i + ": " + cert);

						return cert;
					}
				}
			}
		} else {
			throw new GeneralSecurityException("unexpected PKI body type :" + tagno);
		}

		return null;
	}

	private GeneralPKIMessage buildPKIMessage(byte[] responseBytes) throws IOException, CMPException, CRMFException, GeneralSecurityException {
		GeneralPKIMessage generalPKIMessage = new GeneralPKIMessage(responseBytes);
		printPKIMessageInfo(generalPKIMessage);
		if (generalPKIMessage.hasProtection()) {
			ProtectedPKIMessage protectedPKIMsg = new ProtectedPKIMessage(generalPKIMessage);

			if( protectedPKIMsg.hasPasswordBasedMacProtection()) {
				if (protectedPKIMsg.verify(getMacCalculatorBuilder(), plainSecret.toCharArray())) {
					trace("received response message verified successfully by HMAC");
				} else {
					throw new GeneralSecurityException("received response message failed verification (by HMAC)!");
				}
			}else{
				throw new GeneralSecurityException("received response message has unexpected protection scheme, pbe expected!");
			}
		} else {
			warn("received response message contains NO content protection!");
		}
		return generalPKIMessage;
	}

	/**
	 * build a certificate revocation request
	 * @param certRevId the handle id for the request
	 * @param issuerDN The X500Name of the issuer
	 * @param subjectDN The X500Name of the subject
	 * @param serial the serial
	 * @param crlReason reason the reason as a BC enum 
	 * @return the request as bytes
	 * @throws IOException io interaction failed somehow
	 * @throws CRMFException certificate request related problem
	 * @throws CMPException CMP related problem
	 */
	  public byte[] buildRevocationRequest( long certRevId, final X500Name issuerDN, final X500Name subjectDN, final BigInteger serial, final CRLReason crlReason) 
	          throws IOException, CRMFException,
	          CMPException {
	  
	  
	    // Cert template too tell which cert we want to revoke
	    CertTemplateBuilder myCertTemplate = new CertTemplateBuilder();
	    myCertTemplate.setIssuer(issuerDN);
	    myCertTemplate.setSerialNumber(new ASN1Integer(serial));
	  
	    // Extension telling revocation reason
	    ExtensionsGenerator extgen = new ExtensionsGenerator();
	    extgen.addExtension(Extension.reasonCode, false, crlReason);        
	  
	    Extensions exts = extgen.generate();
	    ASN1EncodableVector v = new ASN1EncodableVector();
	    v.add(myCertTemplate.build());
	    v.add(exts);
	    ASN1Sequence seq = new DERSequence(v);
	    RevDetails myRevDetails = RevDetails.getInstance(seq);
	    RevReqContent myRevReqContent = new RevReqContent(myRevDetails);

	  
	    // get a builder
	    ProtectedPKIMessageBuilder pbuilder = getPKIBuilder(issuerDN, subjectDN);
	  
	    // create the body
	    PKIBody pkiBody = new PKIBody(PKIBody.TYPE_REVOCATION_REQ, myRevReqContent); // revocation request
	    pbuilder.setBody(pkiBody);
	    
	    // get the MacCalculator
	    MacCalculator macCalculator = getMacCalculator(plainSecret);
	    ProtectedPKIMessage message = pbuilder.build(macCalculator);
	    
	    org.bouncycastle.asn1.cmp.PKIMessage pkiMessage = message.toASN1Structure();

    	trace( "sender nonce : " + Base64.toBase64String( pkiMessage.getHeader().getSenderNonce().getOctets() ));

	    return pkiMessage.getEncoded();
	  }


	/**
	 * read the revocation response and check the result
	 * @param responseBytes the returned response as bytes
	 * @return the revocation response object
	 * @throws IOException io interaction failed somehow
	 * @throws CRMFException certificate request related problem
	 * @throws CMPException CMP related problem
	 * @throws GeneralSecurityException something cryptographic went wrong
	 */
	public RevRepContent readRevResponse(final byte[] responseBytes)
			throws IOException, CRMFException, CMPException, GeneralSecurityException {

		GeneralPKIMessage pkiMessage = buildPKIMessage(responseBytes);

		final PKIHeader header = pkiMessage.getHeader();

		if (header.getRecipNonce() == null) {
			trace("no recipient nonce");
		} else {
			trace("recipient nonce : " + Base64.toBase64String(header.getRecipNonce().getOctets()));
		}

		if (header.getSenderNonce() == null) {
			trace("no sender nonce");
		} else {
			trace("sender nonce : " + Base64.toBase64String(header.getSenderNonce().getOctets()));
		}

		final PKIBody body = pkiMessage.getBody();

		int tagno = body.getType();
		if (tagno == PKIBody.TYPE_ERROR) {
			handleCMPError(body);

		} else if (tagno == PKIBody.TYPE_REVOCATION_REP) {

			trace("Rev response received");

			if (body.getContent() != null) {
				RevRepContent revRepContent = RevRepContent.getInstance(body.getContent());

				CertId[] certIdArr = revRepContent.getRevCerts();
				if (certIdArr != null) {
					for (CertId certId : certIdArr) {
						trace("revoked certId : " + certId.getIssuer() + " / " + certId.getSerialNumber().getValue());
					}
				} else {
					trace("no certId ");
				}
				return revRepContent;

			}

		} else {
			throw new GeneralSecurityException("unexpected PKI body type :" + tagno);
		}

		return null;
	}	  

	/**
	 * handle a CMP error response
	 * 
	 * @param body the plain response body
	 * @throws GeneralSecurityException something cryptographic went wrong
	 */
	private void handleCMPError(final PKIBody body) throws GeneralSecurityException {

		String errMsg = "";

		ErrorMsgContent errMsgContent = ErrorMsgContent.getInstance(body.getContent());
		if( errMsgContent.getErrorCode() != null) {
			errMsg = "errMsg : #" + errMsgContent.getErrorCode() + " " + errMsgContent.getErrorDetails() + " / "
					+ errMsgContent.getPKIStatusInfo().getFailInfo();
			log(errMsg);
		}

		try {
			if (errMsgContent.getPKIStatusInfo() != null) {
				PKIFreeText freeText = errMsgContent.getPKIStatusInfo().getStatusString();
				for (int i = 0; i < freeText.size(); i++) {
					trace("#" + i + ": " + freeText.getStringAt(i));
				}
			}
		} catch (NullPointerException npe) { // NOSONAR
			// just ignore
		}

		throw new GeneralSecurityException(errMsg);
	}


	/**
	 * print a PKI message with all its details
	 *
	 * @param pkiMessage a message object
	 */
	private void printPKIMessageInfo(final GeneralPKIMessage pkiMessage) {

		final PKIHeader header = pkiMessage.getHeader();
		final PKIBody body = pkiMessage.getBody();

		trace("Received " + (pkiMessage.hasProtection() ? " protected " : "") + "CMP message with pvno=" + header.getPvno() + ", sender="
				+ header.getSender().toString() + ", recipient=" + header.getRecipient().toString());

		trace("Body is of type: " + body.getType());
		trace("Transaction id: " + header.getTransactionID());
	}


	/**
	 * convert a csr stream to the corresponding BC object
	 * 
	 * @param isCSR the csr input stream
	 * @return the csr input stream 
	 * @throws GeneralSecurityException something cryptographic went wrong
	 */
	public PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(final InputStream isCSR)
			throws GeneralSecurityException {

		PKCS10CertificationRequest csr = null;

		Reader pemReader = new InputStreamReader(isCSR);
		PEMParser pemParser = new PEMParser(pemReader);

		try {
			Object parsedObj = pemParser.readObject();

			if (parsedObj == null) {
				throw new GeneralSecurityException("Parsing of CSR failed! Not PEM encoded?");
			}

//	            LOGGER.debug("PemParser returned: " + parsedObj);

			if (parsedObj instanceof PKCS10CertificationRequest) {
				csr = (PKCS10CertificationRequest) parsedObj;

			}
		} catch (IOException ex) {
			log("IOException, convertPemToPublicKey", ex);
			throw new GeneralSecurityException("Parsing of CSR failed! Not PEM encoded?");
		} finally {
			try {
				pemParser.close();
			} catch (IOException e) {
				// just ignore
				log("IOException on close()", e);
			}
		}

		return csr;
	}

	/**
	 * initialize the message builder with sender and receiver
	 * @param recipientDN The X500Name of the recipient
	 * @param senderDN The X500Name of the sender
	 * @return the initialized builder
	 */
	ProtectedPKIMessageBuilder getPKIBuilder(final X500Name recipientDN, final X500Name senderDN) {

		long rndLong = secRandom.nextLong();

		// senderNonce
		byte[] senderNonce = ("nonce" + rndLong).getBytes();
		// TransactionId
		byte[] transactionId = ("transactionId" + rndLong).getBytes();
		byte[] keyId = ("keyId" + rndLong).getBytes();

		return getPKIBuilder(recipientDN, senderDN, senderNonce, null, transactionId, keyId, null);
	}

	/**
	 * 
	 * @param recipientDN The X500Name of the recipient
	 * @param senderDN The X500Name of the sender
	 * @param senderNonce the sender nonce
	 * @param recipNonce the recipient nonce
	 * @param transactionId the bytes identifying this transaction
	 * @param keyId the bytes identifying the key
	 * @param recipKeyId the bytes identifying the recipient
	 * @return the assembled builder
	 */
	public ProtectedPKIMessageBuilder getPKIBuilder(final X500Name recipientDN, final X500Name senderDN,
			final byte[] senderNonce, final byte[] recipNonce, final byte[] transactionId, final byte[] keyId,
			final byte[] recipKeyId) {

		// Message protection and final message
		GeneralName sender = new GeneralName(senderDN);
		GeneralName recipient = new GeneralName(recipientDN);
		ProtectedPKIMessageBuilder pbuilder = new ProtectedPKIMessageBuilder(sender, recipient);
		pbuilder.setMessageTime(new Date());

		if (senderNonce != null) {
			// senderNonce
			pbuilder.setSenderNonce(senderNonce);
		}

		if (recipNonce != null) {
			// recipNonce
			pbuilder.setRecipNonce(recipNonce);
		}

		if (transactionId != null) {
			pbuilder.setTransactionID(transactionId);
		}

		// Key Id used (required) by the recipient to do a lot of stuff
		if (keyId != null) {
			pbuilder.setSenderKID(keyId);
		}

		if (recipKeyId != null) {
			pbuilder.setRecipKID(recipKeyId);
		}

		return pbuilder;
	}

	

	/**
	 * from string to BC-defined enum
	 * @param revocationReasonStr the revocation reason as a string
	 * @return the enum
	 */
	  public CRLReason crlReasonFromString(final String revocationReasonStr) {

	    int revReason = CRLReason.unspecified;
	    try {
	      revReason = Integer.parseInt(revocationReasonStr);
	    } catch (NumberFormatException nfe) {

//			LOGGER.info("crlReasonFromString for '" + revocationReasonStr + "'", nfe);

	      if ("keyCompromise".equalsIgnoreCase(revocationReasonStr)) {
	        revReason = CRLReason.keyCompromise;
	      } else if ("cACompromise".equalsIgnoreCase(revocationReasonStr)) {
	        revReason = CRLReason.cACompromise;
	      } else if ("affiliationChanged".equalsIgnoreCase(revocationReasonStr)) {
	        revReason = CRLReason.affiliationChanged;
	      } else if ("superseded".equalsIgnoreCase(revocationReasonStr)) {
	        revReason = CRLReason.superseded;
	      } else if ("cessationOfOperation".equalsIgnoreCase(revocationReasonStr)) {
	        revReason = CRLReason.cessationOfOperation;
	      } else if ("privilegeWithdrawn".equalsIgnoreCase(revocationReasonStr)) {
	        revReason = CRLReason.privilegeWithdrawn;
	      } else if ("aACompromise".equalsIgnoreCase(revocationReasonStr)) {
	          revReason = CRLReason.aACompromise;
	      } else if ("certificateHold".equalsIgnoreCase(revocationReasonStr)) {
	          revReason = CRLReason.certificateHold;
	      } else if ("removeFromCRL".equalsIgnoreCase(revocationReasonStr)) {
	          revReason = CRLReason.removeFromCRL;
	      } else if ("unspecified".equalsIgnoreCase(revocationReasonStr)) {
	        revReason = CRLReason.unspecified;
	      }
	    }
	    return CRLReason.lookup(revReason);
	  }


	/**
	 * build a PKMACBuilder
	 * @throws CRMFException creation of the calculator failed
	 * @return the PKMACBuilder object withdefault algorithms
	 */
	public PKMACBuilder getMacCalculatorBuilder() throws CRMFException {

		JcePKMACValuesCalculator jcePkmacCalc = new JcePKMACValuesCalculator();
		final AlgorithmIdentifier digAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26")); // SHA1
		final AlgorithmIdentifier macAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.2.7")); // HMAC/SHA1
		jcePkmacCalc.setup(digAlg, macAlg);
		return new PKMACBuilder(jcePkmacCalc);
	}

	/**
	 * build a HMAC  calculator from a given secret
	 * @param hmacSecret the given secret for this connection
	 * @return the HMACCalculator object
	 * @throws CRMFException creation of the calculator failed
	 */
	public MacCalculator getMacCalculator(final String hmacSecret) throws CRMFException {
		PKMACBuilder macbuilder = getMacCalculatorBuilder();
		return macbuilder.build(hmacSecret.toCharArray());
	}

	/**
	 * get a DER object from a byte array
	 * @param ba the input byte array
	 * @return the ASN1 object
	 * @throws IOException handling went wrong
	 */
	public ASN1Primitive getDERObject(byte[] ba) throws IOException {
		ASN1InputStream ins = new ASN1InputStream(ba);
		try {
			return ins.readObject();
		} finally {
			ins.close();
		}
	}

	/**
	 * build a stringified digest ofd a byte array
	 * @param content the byte array of 
	 * @return the base64 string
	 * @throws GeneralSecurityException something cryptographic went wrong
	 */
	String getHashAsBase64(byte[] content) throws GeneralSecurityException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(content);
		byte[] digest = md.digest();
		return (Base64.toBase64String(digest));
	}

	/**
	 * make a remote http call
	 * 
	 * @param requestUrl the target of the call
	 * @param requestBytes the bytes to be send
	 * @return the received bytes
	 * @throws IOException io handling went wrong
	 */
	public byte[] sendHttpReq(final String requestUrl, final byte[] requestBytes) throws IOException {

		trace("Sending request to: " + requestUrl);

		long startTime = System.currentTimeMillis();

		URL url = new URL(requestUrl);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();

		// we are going to do a POST
		con.setDoOutput(true);
		con.setRequestMethod("POST");

		con.setRequestProperty("Content-Type", "application/octet-stream;charset=UTF-8");

		java.io.OutputStream os = con.getOutputStream();
		os.write(requestBytes);
		os.close();

		// Read the response
		InputStream in = null;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			in = con.getInputStream();

			byte[] tmpBA = new byte[4096];
			int nBytes;
			while ((nBytes = in.read(tmpBA)) > 0) {
				baos.write(tmpBA, 0, nBytes);
			}
			trace("# " + baos.size() + " response bytes recieved");
		} finally {
			if (in != null) {
				in.close();
			}
		}

		if (con.getResponseCode() == 200) {
			trace("Received certificate reply.");
		} else {
			throw new IOException("Error sending CMP request. Response codse != 200 : " + con.getResponseCode());
		}

		// We are done, disconnect
		con.disconnect();

		trace("duration of remote CMP call " + (System.currentTimeMillis() - startTime));

		return baos.toByteArray();
	}

	void warn(String msg){
		System.err.println(" WARN: " +msg);
	}

	void log(String msg){
		System.out.println(" log: " +msg);
	}

	void log(String msg, Exception e){
		System.out.println("  log: " +msg);
		e.printStackTrace();
	}

	void trace(String msg){
		if(verbose) {
			System.out.println("trace: " +msg);
		}
	}

}
