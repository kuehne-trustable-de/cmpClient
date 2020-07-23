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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
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
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.cmp.CMPException;
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
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Simple CMP Client to request or revoke a certificate using the CMP protocol, based on Bouncy Castle
 *
 */
public class CMPClient {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(CMPClient.class);

    SecureRandom secRandom = new SecureRandom();

	private String plainSecret = "foo123";
	private String caUrl = "http://...,"; 
	private String alias = "test";


	private CMPClient() {
        java.security.Security.addProvider( new BouncyCastleProvider() );
	}
	
	public CMPClient(String caUrl, String alias, String plainSecret) {
		this();
		
		this.plainSecret = plainSecret;
		this.caUrl = caUrl; 
		this.alias = alias;
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
		String reason = null;
		String csrFile = "test.csr";
		String certFile = "test.crt";

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
			CMPClient client = new CMPClient( caUrl, alias, plainSecret);
			if( "Request".equals(mode)) {
				
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
			System.err.println("problem occured: " + ex.getLocalizedMessage());
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
		
	}

	public void signCertificateRequest(final File csrFile, final File certFile)
			throws GeneralSecurityException, IOException {
		
		InputStream isCSR = new FileInputStream(csrFile);
		
		X509Certificate cert = signCertificateRequest(isCSR);

		FileOutputStream osCert = new FileOutputStream(certFile);
		osCert.write(cert.getEncoded());
		osCert.close();
		
		LOGGER.info("creation of certificate with subject '{}' succeeded!", cert.getSubjectDN().getName() );

	}
	
	public X509Certificate signCertificateRequest(final InputStream isCSR)
			throws GeneralSecurityException {

		long certReqId = secRandom.nextLong();

		try {

			// build a CMP request from the CSR
			PKIMessage pkiRequest = buildCertRequest(certReqId, isCSR, plainSecret);

			byte[] requestBytes = pkiRequest.getEncoded();

			LOGGER.debug("requestBytes : " + java.util.Base64.getEncoder().encodeToString(requestBytes));
			
			LOGGER.debug("cmp client calls url '{}' with alias '{}' ", caUrl, alias);

			// send and receive ..
			byte[] responseBytes = sendHttpReq(caUrl + "/" + alias, requestBytes);

			if (responseBytes == null) {
				throw new GeneralSecurityException("remote connector returned 'null'");
			}

			LOGGER.debug("responseBytes : " + java.util.Base64.getEncoder().encodeToString(responseBytes));

			// extract the certificate
			X509Certificate cert = readCertResponse(responseBytes, pkiRequest);

			return cert;

		} catch (CRMFException e) {
			LOGGER.info("CMS format problem", e);
			throw new GeneralSecurityException(e.getMessage());
		} catch (CMPException e) {
			LOGGER.info("CMP problem", e);
			throw new GeneralSecurityException(e.getMessage());
		} catch (IOException e) {
			LOGGER.info("IO / encoding problem", e);
			throw new GeneralSecurityException(e.getMessage());
		}
	}

	/**
	 * 
	 * @param x509Cert
	 * @param crlReason
	 * @param hmacSecret
	 * @param cmpEndpoint
	 * @param alias
	 * @throws GeneralSecurityException
	 * @throws IOException 
	 */
	public void revokeCertificate(final File certFile, final String reason) throws GeneralSecurityException, IOException {

		InputStream isCert = new FileInputStream(certFile);
		try {

			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			X509Certificate x509Cert = (X509Certificate) certificateFactory.generateCertificate(isCert);

			CRLReason crlReason = crlReasonFromString(reason);
			
			revokeCertificate(JcaX500NameUtil.getIssuer(x509Cert), JcaX500NameUtil.getSubject(x509Cert),
					x509Cert.getSerialNumber(), crlReason);

			LOGGER.info("revocation of certificate '{}' with reason '{}' succeeded!", x509Cert.getSubjectDN().getName(), reason);

		} finally {
			isCert.close();
		}
	}
	/**
	 * 
	 * @param csr
	 * @param user
	 * @param password
	 * @param hmacSecret
	 * @param cmpEndpoint
	 * @param alias
	 * @return
	 * @throws GeneralSecurityException
	 */
	public void revokeCertificate(final X500Name issuerDN, final X500Name subjectDN, final BigInteger serial,
			final CRLReason crlReason)
			throws GeneralSecurityException {

		long certRevId = new Random().nextLong();

		try {

			// build a CMP request from the revocation infos
			byte[] revocationRequestBytes = buildRevocationRequest(certRevId, issuerDN, subjectDN, serial, crlReason);

			// send and receive ..
			LOGGER.debug("revocation requestBytes : " + java.util.Base64.getEncoder().encodeToString(revocationRequestBytes));
			byte[] responseBytes = sendHttpReq(caUrl + "/" + alias, revocationRequestBytes);
			LOGGER.debug("revocation responseBytes : " + java.util.Base64.getEncoder().encodeToString(responseBytes));

			// handle the response
			readRevResponse(responseBytes);

			return;

		} catch (CRMFException e) {
			LOGGER.info("CMS format problem", e);
			throw new GeneralSecurityException(e.getMessage());
		} catch (CMPException e) {
			LOGGER.info("CMP problem", e);
			throw new GeneralSecurityException(e.getMessage());
		} catch (IOException e) {
			LOGGER.info("IO / encoding problem", e);
			throw new GeneralSecurityException(e.getMessage());
		}
	}

	/**
	 * 
	 * @param certReqId
	 * @param csr
	 * @param publicKey
	 * @param hmacSecret
	 * @return
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public PKIMessage buildCertRequest(long certReqId, final InputStream isCSR, final String hmacSecret)
			throws GeneralSecurityException {

		PKCS10CertificationRequest p10Req = convertPemToPKCS10CertificationRequest(isCSR);

		X500Name subjectDN = p10Req.getSubject();
		LOGGER.debug("subjectDN : " + subjectDN.toString());

		Collection<Extension> certExtList = new ArrayList<Extension>();

		final SubjectPublicKeyInfo keyInfo = p10Req.getSubjectPublicKeyInfo();

		return buildCertRequest(certReqId, p10Req.getSubject(), certExtList, keyInfo, hmacSecret);

	}

	/**
	 * 
	 * @param certReqId
	 * @param subjectDN
	 * @param certExtList
	 * @param keyInfo
	 * @param hmacSecret
	 * @return
	 * @throws GeneralSecurityException
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

				LOGGER.debug("Csr Extension : " + ext.getExtnId().getId() + " -> " + ext.getExtnValue());

				boolean critical = false;
				msgbuilder.addExtension(ext.getExtnId(), critical, ext.getParsedValue());
			}

			msgbuilder.setPublicKey(keyInfo);
			GeneralName sender = new GeneralName(subjectDN);
			msgbuilder.setAuthInfoSender(sender);

			// RAVerified POP
			msgbuilder.setProofOfPossessionRaVerified();

			CertificateRequestMessage msg = msgbuilder.build();

			LOGGER.debug("CertTemplate : " + msg.getCertTemplate());

			ProtectedPKIMessageBuilder pbuilder = getPKIBuilder(issuerDN, subjectDN);

			CertReqMessages msgs = new CertReqMessages(msg.toASN1Structure());
			PKIBody pkibody = new PKIBody(PKIBody.TYPE_INIT_REQ, msgs);
			pbuilder.setBody(pkibody);

			MacCalculator macCalculator = getMacCalculator(hmacSecret);
			ProtectedPKIMessage message = pbuilder.build(macCalculator);

			org.bouncycastle.asn1.cmp.PKIMessage pkiMessage = message.toASN1Structure();

			return pkiMessage;

		} catch (CRMFException | CMPException | IOException crmfe) {
			LOGGER.warn("Exception occured processing extensions", crmfe);
			throw new GeneralSecurityException(crmfe.getMessage());
		}
	}


	/**
	 * 
	 * 
	 * @param responseBytes
	 * @param pkiRequest
	 * @return
	 * @throws IOException
	 * @throws CRMFException
	 * @throws CMPException
	 * @throws GeneralSecurityException
	 */
	public X509Certificate readCertResponse(final byte[] responseBytes,
			final PKIMessage pkiMessageReq)
			throws IOException, CRMFException, CMPException, GeneralSecurityException {

		final ASN1Primitive derObject = getDERObject(responseBytes);
		final PKIMessage pkiMessage = PKIMessage.getInstance(derObject);
		if (pkiMessage == null) {
			throw new GeneralSecurityException("No CMP message could be parsed from received Der object.");
		}

		printPKIMessageInfo(pkiMessage);

		PKIHeader pkiHeaderReq = pkiMessageReq.getHeader();
		PKIHeader pkiHeaderResp = pkiMessage.getHeader();

		if (!pkiHeaderReq.getSenderNonce().equals(pkiHeaderResp.getRecipNonce())) {
			ASN1OctetString asn1Oct = pkiHeaderResp.getRecipNonce();
			if (asn1Oct == null) {
				LOGGER.info("Recip nonce  == null");
			} else {
				LOGGER.info("sender nonce "
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
				LOGGER.info("transaction id == null");
			} else {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("transaction id "
							+ java.util.Base64.getEncoder().encodeToString(pkiHeaderReq.getTransactionID().getOctets())
							+ " != " + java.util.Base64.getEncoder().encodeToString(asn1Oct.getOctets()));
				}
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
				LOGGER.info("CMP Response body contains " + cmpCertArr.length + " extra certificates");
				for (int i = 0; i < cmpCertArr.length; i++) {
					CMPCertificate cmpCert = cmpCertArr[i];
					LOGGER.info("Added CA '" + cmpCert.getX509v3PKCert().getSubject() + "' from CMP Response body");
					// store if required ...
				}
			} catch (NullPointerException npe) { // NOSONAR
				// just ignore
			}

			CertResponse[] respArr = certRepMessage.getResponse();
			if (respArr == null || (respArr.length == 0)) {
				throw new GeneralSecurityException("No CMP response found.");
			}

			LOGGER.info("CMP Response body contains " + respArr.length + " elements");

			for (int i = 0; i < respArr.length; i++) {

				if (respArr[i] == null) {
					throw new GeneralSecurityException("No CMP response returned.");
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

						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("#" + i + ": " + cmpCertificate);
						}

						final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");

						/*
						 * version returning just the end entity ...
						 */
						final Collection<? extends java.security.cert.Certificate> certificateChain = certificateFactory
								.generateCertificates(new ByteArrayInputStream(cmpCertificate.getEncoded()));

						X509Certificate[] certArray = certificateChain.toArray(new X509Certificate[0]);

						X509Certificate cert = certArray[0];
						if (LOGGER.isDebugEnabled()) {
							LOGGER.info("#" + i + ": " + cert);
						}

						return cert;
					}
				}
			}
		} else {
			throw new GeneralSecurityException("unexpected PKI body type :" + tagno);
		}

		return null;
	}

	/**
	 * 
	 * @param certRevId
	 * @param issuerDN
	 * @param subjectDN
	 * @param serial
	 * @param crlReason
	 * @param hmacSecret
	 * @return
	 * @throws IOException
	 * @throws CRMFException
	 * @throws CMPException
	 * @throws GeneralSecurityException
	 */
	  public byte[] buildRevocationRequest( long certRevId, final X500Name issuerDN, final X500Name subjectDN, final BigInteger serial, final CRLReason crlReason) 
	          throws IOException, CRMFException,
	          CMPException, GeneralSecurityException {
	  
	  
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

	    if( LOGGER.isDebugEnabled() ){
	    	LOGGER.debug( "sender nonce : " + Base64.toBase64String( pkiMessage.getHeader().getSenderNonce().getOctets() ));
	    }
	    
	    return pkiMessage.getEncoded();
	  }


	  /**
	   * 
	   * @param caConnector TODO
	   * @param responseBytes
	   * @return
	   * @throws IOException
	   * @throws CRMFException
	   * @throws CMPException
	   * @throws GeneralSecurityException
	   */
	public RevRepContent readRevResponse(final byte[] responseBytes)
			throws IOException, CRMFException, CMPException, GeneralSecurityException {

		final ASN1Primitive derObject = getDERObject(responseBytes);

		final PKIMessage pkiMessage = PKIMessage.getInstance(derObject);
		if (pkiMessage == null) {
			throw new GeneralSecurityException("No CMP message could be parsed from received Der object.");
		}

		final PKIHeader header = pkiMessage.getHeader();

		if (header.getRecipNonce() == null) {
			LOGGER.debug("no recip nonce");
		} else {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("recip nonce : " + Base64.toBase64String(header.getRecipNonce().getOctets()));
			}
		}

		if (header.getSenderNonce() == null) {
			LOGGER.debug("no sender nonce");
		} else {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("sender nonce : " + Base64.toBase64String(header.getSenderNonce().getOctets()));
			}
		}

		final PKIBody body = pkiMessage.getBody();

		int tagno = body.getType();

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Received CMP message with pvno=" + header.getPvno() + ", sender="
					+ header.getSender().toString() + ", recipient=" + header.getRecipient().toString());
			LOGGER.debug("Body is of type: " + tagno);
			LOGGER.debug("Transaction id: " + header.getTransactionID());
		}
		if (tagno == PKIBody.TYPE_ERROR) {
			handleCMPError(body);

		} else if (tagno == PKIBody.TYPE_REVOCATION_REP) {

			LOGGER.debug("Rev response received");

			if (body.getContent() != null) {
				RevRepContent revRepContent = RevRepContent.getInstance(body.getContent());

				CertId[] certIdArr = revRepContent.getRevCerts();
				if (certIdArr != null) {
					for (CertId certId : certIdArr) {
						LOGGER.info(
								"revoked certId : " + certId.getIssuer() + " / " + certId.getSerialNumber().getValue());
					}
				} else {
					LOGGER.debug("no certId ");
				}
				return revRepContent;

			}

		} else {
			throw new GeneralSecurityException("unexpected PKI body type :" + tagno);
		}

		return null;
	}	  

	/**
	 * @param body
	 * @throws GeneralSecurityException
	 */
	private void handleCMPError(final PKIBody body) throws GeneralSecurityException {

		ErrorMsgContent errMsgContent = ErrorMsgContent.getInstance(body.getContent());
		String errMsg = "errMsg : #" + errMsgContent.getErrorCode() + " " + errMsgContent.getErrorDetails() + " / "
				+ errMsgContent.getPKIStatusInfo().getFailInfo();

		LOGGER.info(errMsg);

		try {
			if (errMsgContent != null && errMsgContent.getPKIStatusInfo() != null) {
				PKIFreeText freeText = errMsgContent.getPKIStatusInfo().getStatusString();
				for (int i = 0; i < freeText.size(); i++) {
					LOGGER.info("#" + i + ": " + freeText.getStringAt(i));
				}
			}
		} catch (NullPointerException npe) { // NOSONAR
			// just ignore
		}

		throw new GeneralSecurityException(errMsg);
	}

	/**
	 * @param pkiMessage
	 * @return
	 */
	private void printPKIMessageInfo(final PKIMessage pkiMessage) {

		final PKIHeader header = pkiMessage.getHeader();
		final PKIBody body = pkiMessage.getBody();

		int tagno = body.getType();
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Received CMP message with pvno=" + header.getPvno() + ", sender="
					+ header.getSender().toString() + ", recipient=" + header.getRecipient().toString());
			LOGGER.debug("Body is of type: " + tagno);
			LOGGER.debug("Transaction id: " + header.getTransactionID());
		}
	}

	/**
	 * 
	 * @param certRevId
	 * @param issuerDN
	 * @param subjectDN
	 * @param serial
	 * @param crlReason
	 * @param hmacSecret
	 * @return
	 * @throws IOException
	 * @throws CRMFException
	 * @throws CMPException
	 * @throws GeneralSecurityException
	 */
	public byte[] buildRevocationRequest(long certRevId, final X500Name issuerDN, final X500Name subjectDN,
			final BigInteger serial, final CRLReason crlReason, final String hmacSecret)
			throws IOException, CRMFException, CMPException, GeneralSecurityException {

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
		MacCalculator macCalculator = getMacCalculator(hmacSecret);
		ProtectedPKIMessage message = pbuilder.build(macCalculator);

		org.bouncycastle.asn1.cmp.PKIMessage pkiMessage = message.toASN1Structure();

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(
					"sender nonce : " + Base64.toBase64String(pkiMessage.getHeader().getSenderNonce().getOctets()));
		}

		return pkiMessage.getEncoded();
	}

	/**
	 * 
	 * @param pem
	 * @return
	 * @throws GeneralSecurityException
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
			LOGGER.error("IOException, convertPemToPublicKey", ex);
			throw new GeneralSecurityException("Parsing of CSR failed! Not PEM encoded?");
		} finally {
			try {
				pemParser.close();
			} catch (IOException e) {
				// just ignore
				LOGGER.debug("IOException on close()", e);
			}
		}

		return csr;
	}

	/**
	 * 
	 * @param recipientDN
	 * @param senderDN
	 * @return
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
	 * @param recipientDN
	 * @param senderDN
	 * @param senderNonce
	 * @param recipNonce
	 * @param transactionId
	 * @param keyId
	 * @param recipKeyId
	 * @return
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
	 * 
	 * @param revocationReasonStr
	 * @return
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
	 * 
	 * @param hmacSecret
	 * @return
	 * @throws CRMFException
	 */
	public MacCalculator getMacCalculator(final String hmacSecret) throws CRMFException {

		JcePKMACValuesCalculator jcePkmacCalc = new JcePKMACValuesCalculator();
		final AlgorithmIdentifier digAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26")); // SHA1
		final AlgorithmIdentifier macAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.2.7")); // HMAC/SHA1
		jcePkmacCalc.setup(digAlg, macAlg);
		PKMACBuilder macbuilder = new PKMACBuilder(jcePkmacCalc);
		MacCalculator macCalculator = macbuilder.build(hmacSecret.toCharArray());
		return macCalculator;
	}

	/**
	 * 
	 * @param ba
	 * @return
	 * @throws IOException
	 */
	public ASN1Primitive getDERObject(byte[] ba) throws IOException {
		ASN1InputStream ins = new ASN1InputStream(ba);
		try {
			ASN1Primitive obj = ins.readObject();
			return obj;
		} finally {
			ins.close();
		}
	}

	/**
	 * 
	 * @param content
	 * @return
	 * @throws GeneralSecurityException
	 */
	String getHashAsBase64(byte[] content) throws GeneralSecurityException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(content);
		byte[] digest = md.digest();
		return (Base64.toBase64String(digest));
	}

	/**
	 * 
	 * @param requestUrl
	 * @param requestBytes
	 * @return
	 * @throws IOException
	 */
	public byte[] sendHttpReq(final String requestUrl, final byte[] requestBytes) throws IOException {

		LOGGER.debug("Sending request to: " + requestUrl);

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
			int nBytes = 0;
			while ((nBytes = in.read(tmpBA)) > 0) {
				baos.write(tmpBA, 0, nBytes);
			}
			LOGGER.debug("# " + baos.size() + " response bytes recieved");
		} finally {
			if (in != null) {
				in.close();
			}
		}

		if (con.getResponseCode() == 200) {
			LOGGER.debug("Received certificate reply.");
		} else {
			throw new IOException("Error sending CMP request. Response codse != 200 : " + con.getResponseCode());
		}

		// We are done, disconnect
		con.disconnect();

		LOGGER.debug("duration of remote CMP call " + (System.currentTimeMillis() - startTime));

		return baos.toByteArray();
	}


}
