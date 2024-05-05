package de.trustable.cmp.client.cmpClient;

/*
   Copyright 2022 Andreas Kuehne

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

 */

import de.trustable.cmp.client.ProtectedMessageHandler;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;


/**
 * Simple CMP Client to request or revoke a certificate using the CMP protocol, based on Bouncy Castle
 *
 */
public class CMPClientImpl {

	private static final Logger LOGGER = LoggerFactory.getLogger(CMPClientImpl.class);

	SecureRandom secRandom = new SecureRandom();

	private CMPClientConfig cmpClientConfig;

	private CMPClientImpl() {
        Security.addProvider( new BouncyCastleProvider() );
	}

	public CMPClientImpl(final CMPClientConfig cmpClientConfig){
		this();
		this.cmpClientConfig = cmpClientConfig;
	}

	public GenMsgContent getGeneralMessageRequest()
			throws GeneralSecurityException {

		try {
			X500Name subjectDN = X500Name.getInstance(new X500Name("CN=User1").toASN1Primitive());
			PKIMessage pkiRequest = buildGeneralMessageRequest( subjectDN, cmpClientConfig.getMessageHandler());

			ASN1Object requestContent = pkiRequest;
			if(cmpClientConfig.isMultipleMessages()){
				trace("wrapping PKIMessage into PKIMessages");
				requestContent = new PKIMessages(pkiRequest);
			}
			byte[] requestBytes = requestContent.getEncoded();

			if(cmpClientConfig.isVerbose()) {
				File dumpRequestFile = File.createTempFile("cmp_request_dump", ".der");
				try (FileOutputStream fos = new FileOutputStream(dumpRequestFile)) {
					fos.write(requestBytes);
				}
				trace("requestBytes in dump file : " + dumpRequestFile.getAbsolutePath());

				trace("requestBytes : " + java.util.Base64.getEncoder().encodeToString(requestBytes));
				trace("cmp client calls url '" + cmpClientConfig.getCaUrl() + "' with alias '" + cmpClientConfig.getCmpAlias() + "'");
			}


			// send and receive ..
			byte[] responseBytes = cmpClientConfig.getRemoteTargetHandler().sendHttpReq(cmpClientConfig.getCaUrl() + "/" + cmpClientConfig.getCmpAlias(),
					requestBytes,
					cmpClientConfig.getMsgContentType(),
					cmpClientConfig.getSni(),
					false,
					cmpClientConfig.getP12ClientStore(),
					cmpClientConfig.getP12ClientSecret());

			if (responseBytes == null) {
				throw new GeneralSecurityException("remote connector returned 'null'");
			}

			if(cmpClientConfig.isVerbose()) {
				File dumpResponseFile = File.createTempFile("cmp_response_dump", ".der");
				try (FileOutputStream fos = new FileOutputStream(dumpResponseFile)) {
					fos.write(responseBytes);
				}
				trace("responseBytes in dump file : " + dumpResponseFile.getAbsolutePath());
				trace("responseBytes : " + java.util.Base64.getEncoder().encodeToString(responseBytes));
			}

			// extract the certificate
			return readGenMsgResponse(responseBytes);


		} catch (IOException e) {
			log("IO / encoding problem", e);
			throw new GeneralSecurityException(e.getMessage());
		}
	}


	public CertificateResponseContent signCertificateRequest(final InputStream isCSR)
			throws GeneralSecurityException {

		PKCS10CertificationRequest p10Req = convertPemToPKCS10CertificationRequest(isCSR);
		return signCertificateRequest(p10Req);
	}

	public CertificateResponseContent signCertificateRequest(final PKCS10CertificationRequest p10Req)
			throws GeneralSecurityException {

		long certReqId = secRandom.nextLong();

		try {

			// build a CMP request from the CSR
			PKIMessage pkiRequest = buildCertRequest(certReqId, p10Req, cmpClientConfig.getMessageHandler());

			ASN1Object requestContent = pkiRequest;
			if(cmpClientConfig.isMultipleMessages()){
				trace("wrapping PKIMessage into PKIMessages");
				requestContent = new PKIMessages(pkiRequest);
			}
			byte[] requestBytes = requestContent.getEncoded();

			if(cmpClientConfig.isVerbose()) {
				File dumpRequestFile = File.createTempFile("cmp_request_dump", ".der");
				try (FileOutputStream fos = new FileOutputStream(dumpRequestFile)) {
					fos.write(requestBytes);
				}
				trace("requestBytes in dump file : " + dumpRequestFile.getAbsolutePath());

				trace("requestBytes : " + java.util.Base64.getEncoder().encodeToString(requestBytes));
				trace("cmp client calls url '" + cmpClientConfig.getCaUrl() + "' with alias '" + cmpClientConfig.getCmpAlias() + "'");
			}

			// send and receive ..
			byte[] responseBytes = cmpClientConfig.getRemoteTargetHandler().sendHttpReq(cmpClientConfig.getCaUrl() + "/" + cmpClientConfig.getCmpAlias(),
					requestBytes,
					cmpClientConfig.getMsgContentType(),
					cmpClientConfig.getSni(),
					cmpClientConfig.isDisableHostNameVerifier(),
					cmpClientConfig.getP12ClientStore(),
					cmpClientConfig.getP12ClientSecret());

			if (responseBytes == null) {
				throw new GeneralSecurityException("remote connector returned 'null'");
			}

			if(cmpClientConfig.isVerbose()) {
				File dumpResponseFile = File.createTempFile("cmp_response_dump", ".der");
				try (FileOutputStream fos = new FileOutputStream(dumpResponseFile)) {
					fos.write(responseBytes);
				}
				trace("responseBytes in dump file : " + dumpResponseFile.getAbsolutePath());
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

		try(InputStream isCert = new FileInputStream(certFile)) {

			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			X509Certificate x509Cert = (X509Certificate) certificateFactory.generateCertificate(isCert);

			CRLReason crlReason = crlReasonFromString(reason);

			revokeCertificate(JcaX500NameUtil.getIssuer(x509Cert), JcaX500NameUtil.getSubject(x509Cert),
					x509Cert.getSerialNumber(), crlReason);

			log("revocation of certificate '"+x509Cert.getSubjectDN().getName()+"' with reason '"+reason+"' succeeded!");
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
			byte[] responseBytes = cmpClientConfig.getRemoteTargetHandler().sendHttpReq(cmpClientConfig.getCaUrl() + "/" + cmpClientConfig.getCmpAlias(),
					revocationRequestBytes,
					cmpClientConfig.getMsgContentType(),
					cmpClientConfig.getSni(),
					cmpClientConfig.isDisableHostNameVerifier(),
					cmpClientConfig.getP12ClientStore(),
					cmpClientConfig.getP12ClientSecret());
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

	public PKIMessage buildGeneralMessageRequest(final X500Name subjectDN,
												 final ProtectedMessageHandler messageHandler)
			throws GeneralSecurityException {

		InfoTypeAndValue[] itvArr = new InfoTypeAndValue[1];
		itvArr[0] = new InfoTypeAndValue( CMPObjectIdentifiers.id_regCtrl_algId);
		GenMsgContent genMsgContent = new GenMsgContent(itvArr);

		X500Name recipientDN = new X500Name( new RDN[0] );
		X500Name sender = messageHandler.getSender(subjectDN);
		ProtectedPKIMessageBuilder pbuilder = getPKIBuilder(recipientDN, sender);

		messageHandler.addCertificate(pbuilder);

		// create the body
		PKIBody pkiBody = new PKIBody(PKIBody.TYPE_GEN_MSG, genMsgContent); // general message request
		pbuilder.setBody(pkiBody);

		ProtectedPKIMessage message = messageHandler.signMessage(pbuilder);

		PKIMessage pkiMessage = message.toASN1Structure();

		return pkiMessage;

	}

	/**
	 *
	 * @param responseBytes
	 * @return
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public GenMsgContent readGenMsgResponse( final byte[] responseBytes)
			throws IOException,
			GeneralSecurityException {

		PKIMessage pkiMessage = getPkiMessage(responseBytes);

		final PKIHeader header = pkiMessage.getHeader();

		if( LOGGER.isDebugEnabled()){
			if( header.getRecipNonce() == null){
				LOGGER.debug( "no recip nonce");
			}else{
				LOGGER.debug( "recip nonce : " + Base64.toBase64String( header.getRecipNonce().getOctets() ));
			}

			if( header.getSenderNonce() == null){
				LOGGER.debug( "no sender nonce");
			}else{
				LOGGER.debug( "sender nonce : " + Base64.toBase64String( header.getSenderNonce().getOctets() ));
			}
		}

		final PKIBody body = pkiMessage.getBody();

		int tagno = body.getType();

		if( LOGGER.isDebugEnabled()){
			LOGGER.debug("Received CMP message with pvno=" + header.getPvno()
					+ ", sender=" + header.getSender().toString() + ", recipient="
					+ header.getRecipient().toString());
			LOGGER.debug("Body is of type: " + tagno);
			LOGGER.debug("Transaction id: " + header.getTransactionID());
		}

		if (tagno == PKIBody.TYPE_ERROR) {
			handleCMPError(body);

		} else if (tagno == PKIBody.TYPE_GEN_REP ) {

			LOGGER.debug("Rev response received");

			if( body.getContent() != null ){
				GenMsgContent genMsgContent = GenMsgContent.getInstance(body.getContent());

				InfoTypeAndValue[] infoTypeAndValueArr = genMsgContent.toInfoTypeAndValueArray();
				if( infoTypeAndValueArr != null ){
					for( InfoTypeAndValue infoTypeAndValue: infoTypeAndValueArr){
						LOGGER.info("infoTypeAndValue : " + infoTypeAndValue.getInfoType()+ " / " + infoTypeAndValue.getInfoValue());
					}
				}else{
					LOGGER.debug("no certId ");
				}
				return genMsgContent;

			}

		} else {
			throw new GeneralSecurityException("unexpected PKI body type :" + tagno);
		}

		return null;
	}



	/**
	 * build the CMP request message
	 * @param certReqId the handle id for the request
	 * @param p10Req input CSR object
	 * @param signer an implementation for message authentication
	 * @return the CMP request message
	 * @throws GeneralSecurityException something cryptographic went wrong
	 */
	public PKIMessage buildCertRequest(long certReqId, final PKCS10CertificationRequest p10Req, final ProtectedMessageHandler signer)
			throws GeneralSecurityException {

		final SubjectPublicKeyInfo keyInfo = p10Req.getSubjectPublicKeyInfo();

		try {
			if( !p10Req.isSignatureValid(new JcaContentVerifierProviderBuilder().build(keyInfo))){
				throw new GeneralSecurityException("CSR signature validation failed");
			}
		} catch (PKCSException | OperatorCreationException e) {
			throw new GeneralSecurityException(e);
		}

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
		return buildCertRequest(certReqId, p10Req.getSubject(), certExtList, keyInfo, signer);
	}


	/**
	 *
	 * @param certReqId the handle id for the request
	 * @param subjectDN The X500Name of the subject
	 * @param certExtList a collection o extensions, eg SANS
	 * @param keyInfo the identification data of the key
	 * @param messageHandler an implementation for message authentication
	 * @return the CMP request message
	 * @throws GeneralSecurityException something cryptographic went wrong
	 */
	public PKIMessage buildCertRequest(long certReqId,
									   final X500Name subjectDN,
									   final Collection<Extension> certExtList,
									   final SubjectPublicKeyInfo keyInfo,
									   final ProtectedMessageHandler messageHandler)
			throws GeneralSecurityException {

		JcaCertificateRequestMessageBuilder msgbuilder = new JcaCertificateRequestMessageBuilder(BigInteger.valueOf(certReqId));
		if( cmpClientConfig.getATaVArr() != null && cmpClientConfig.getATaVArr().length > 0) {
			msgbuilder.setRegInfo(cmpClientConfig.getATaVArr());
			trace("added " + cmpClientConfig.getATaVArr().length + " ATaVs to the request");
		}

		msgbuilder.setSubject(subjectDN);
		trace("set subject to '" + subjectDN + "'");

		X500Name recipientDN = new X500Name( new RDN[0] );

		try {

			for (Extension ext : certExtList) {
				trace("Add csr Extension : " + ext.getExtnId().getId() + " -> " + ext.getExtnValue());
				boolean critical = ext.isCritical();
				msgbuilder.addExtension(ext.getExtnId(), critical, ext.getExtnValue().getOctets());
			}

			msgbuilder.setPublicKey(keyInfo);

//			GeneralName sender = new GeneralName(subjectDN);
//			msgbuilder.setAuthInfoSender(sender);

			// RAVerified POP
			// I am a  client, I do trust my master!
			msgbuilder.setProofOfPossessionRaVerified();

			cmpClientConfig.handleIssuer(msgbuilder);

			CertificateRequestMessage msg = msgbuilder.build();
			trace("CertTemplate : " + msg.getCertTemplate());

			X500Name sender = messageHandler.getSender(subjectDN);
			ProtectedPKIMessageBuilder pbuilder = getPKIBuilder(recipientDN, sender);

			if (cmpClientConfig.isImplicitConfirm()) {
				pbuilder.addGeneralInfo(new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE));
			}

			messageHandler.addCertificate(pbuilder);
/*
			if( messageHandler instanceof KeystoreSigner) {
				X509CertificateHolder certificateHolder = new X509CertificateHolder(((KeystoreSigner)messageHandler).getSignerCertificate().getEncoded());
				pbuilder.addCMPCertificate(certificateHolder);
			}
/*

 */
			CertReqMessages msgs = new CertReqMessages(msg.toASN1Structure());
//			PKIBody pkibody = new PKIBody(PKIBody.TYPE_INIT_REQ, msgs);
			PKIBody pkibody = new PKIBody(PKIBody.TYPE_CERT_REQ, msgs);
			pbuilder.setBody(pkibody);
			ProtectedPKIMessage message = messageHandler.signMessage(pbuilder);

			return message.toASN1Structure();

		} catch (CRMFException crmfe) {
			log("Exception occurred processing extensions", crmfe);
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
	public CertificateResponseContent readCertResponse(final byte[] responseBytes,
											final PKIMessage pkiMessageReq)
			throws IOException, CRMFException, CMPException, GeneralSecurityException {

		CertificateResponseContent responseContent = new CertificateResponseContent();

		PKIMessage pkiMessage = getPkiMessage(responseBytes);

		// validate protected messages
		buildPKIMessage(pkiMessage);

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
				throw new GeneralSecurityException("Sender / Recip nonce mismatch");
			}
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
			if( cmpClientConfig.isCheckTransactionIdMatch()) {
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
		}

		final PKIBody body = pkiMessage.getBody();

		int tagno = body.getType();

		if (tagno == PKIBody.TYPE_ERROR) {
			handleCMPError(body);

		} else if (tagno == PKIBody.TYPE_CERT_REP || tagno == PKIBody.TYPE_INIT_REP) {
			// certificate successfully generated
			CertRepMessage certRepMessage = CertRepMessage.getInstance(body.getContent());

			handleExtraCerts(certRepMessage.getCaPubs(), responseContent);
			handleExtraCerts(pkiMessage.getExtraCerts(), responseContent);

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
							statusText += freeText.getStringAt(j) + "\n";
						}
					}
				}
				responseContent.setMessage(statusText);

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
						final Collection<? extends Certificate> certificateChain = certificateFactory
								.generateCertificates(new ByteArrayInputStream(cmpCertificate.getEncoded()));

						X509Certificate[] certArray = certificateChain.toArray(new X509Certificate[0]);

						responseContent.setCreatedCertificate( certArray[0]);
						return responseContent;
					}
				}
			}
		} else {
			throw new GeneralSecurityException("unexpected PKI body type :" + tagno);
		}

		return null;
	}

	private void handleExtraCerts(final CMPCertificate[] cmpCertArr, CertificateResponseContent responseContent) throws GeneralSecurityException, IOException {
		if( cmpCertArr == null){
			// no additional certs
			return;
		}

		CertificateFactory factory = CertificateFactory.getInstance("X.509");

		LOGGER.info("CMP response contains " + cmpCertArr.length + " extra certificates");
		for (int i = 0; i < cmpCertArr.length; i++) {
			try {
				CMPCertificate cmpCert = cmpCertArr[i];
				LOGGER.info("Additional cert '" + cmpCert.getX509v3PKCert().getSubject() + "' included in CMP response");
				try {
					X509Certificate cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(cmpCert.getEncoded()));
					responseContent.additionalCertificates.add(cert);
				} catch (GeneralSecurityException | IOException e) {
					LOGGER.info("problem importing certificate: " + e.getMessage(), e);
					throw e;
				} catch (Throwable th) {
					LOGGER.info("problem importing certificate: " + th.getMessage(), th);
					throw new GeneralSecurityException("problem importing certificate: " + th.getMessage());
				}

			} catch (NullPointerException npe) { // NOSONAR
				// just ignore
			}
		}
	}


	private PKIMessage getPkiMessage(byte[] responseBytes) throws IOException, GeneralSecurityException {
		final ASN1Primitive derObject = getDERObject(responseBytes);

		PKIMessage pkiMessage = null;

		try {
			final PKIMessages pkiMessages = PKIMessages.getInstance(derObject);
			PKIMessage[] messageArr = pkiMessages.toPKIMessageArray();
			if( messageArr.length > 0) {
				pkiMessage = messageArr[0];
			}
		} catch( Throwable th){
			log("reading PKIMessages failed: " + th.getMessage());
		}

		if (pkiMessage == null) {
			pkiMessage = PKIMessage.getInstance(derObject);
		}

		if (pkiMessage == null) {
			throw new GeneralSecurityException("No CMP message could be parsed from received DER object.");
		}
		return pkiMessage;
	}

	private GeneralPKIMessage buildPKIMessage(final PKIMessage pkiMessage) throws GeneralSecurityException {
		GeneralPKIMessage generalPKIMessage = new GeneralPKIMessage(pkiMessage);
		printPKIMessageInfo(generalPKIMessage);
		if (generalPKIMessage.hasProtection()) {
			ProtectedPKIMessage protectedPKIMsg = new ProtectedPKIMessage(generalPKIMessage);

			if( cmpClientConfig.getMessageHandler().verifyMessage(protectedPKIMsg)){
				trace( "message verification success");
			}else{
				throw new GeneralSecurityException("received response message has unexpected protection scheme!");
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
	 * @throws GeneralSecurityException General security problem
	 */
	public byte[] buildRevocationRequest( long certRevId, final X500Name issuerDN, final X500Name subjectDN, final BigInteger serial, final CRLReason crlReason)
			throws IOException, CRMFException,
			CMPException, GeneralSecurityException {


		// Cert template to tell which cert we want to revoke
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

		ProtectedMessageHandler protectedMessageHandler = cmpClientConfig.getMessageHandler();

		// get a builder
		X500Name sender = protectedMessageHandler.getSender(subjectDN);
		ProtectedPKIMessageBuilder pbuilder = getPKIBuilder(issuerDN, sender);

		// create the body
		PKIBody pkiBody = new PKIBody(PKIBody.TYPE_REVOCATION_REQ, myRevReqContent); // revocation request
		pbuilder.setBody(pkiBody);

		protectedMessageHandler.addCertificate(pbuilder);

		if (cmpClientConfig.isImplicitConfirm()) {
			pbuilder.addGeneralInfo(new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE));
		}

		ProtectedPKIMessage message = protectedMessageHandler.signMessage(pbuilder);

		PKIMessage pkiMessage = message.toASN1Structure();
		trace( "sender nonce : " + Base64.toBase64String( pkiMessage.getHeader().getSenderNonce().getOctets() ));

		ASN1Object requestContent = pkiMessage;
		if(cmpClientConfig.isMultipleMessages()){
			trace("wrapping PKIMessage into PKIMessages");
			requestContent = new PKIMessages(pkiMessage);
		}

		return requestContent.getEncoded();
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

		GeneralPKIMessage pkiMessage = buildPKIMessage(getPkiMessage(responseBytes));

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
		if( errMsgContent.getErrorCode() != null || errMsgContent.getErrorDetails() != null ) {

			errMsg = "errMsg :";

			if( errMsgContent.getErrorCode() != null ) {
				errMsg += " #" + errMsgContent.getErrorCode();
			}

			if( errMsgContent.getErrorDetails() != null ) {
				errMsg += " " + errMsgContent.getErrorDetails();
			}
/*
			if( errMsgContent.getPKIStatusInfo() != null  &&
					errMsgContent.getPKIStatusInfo().getFailInfo() != null ) {
				errMsg += " " + errMsgContent.getPKIStatusInfo().getFailInfo() + " " +
						errMsgContent.getPKIStatusInfo().getStatusString().toString();
			}

 */
		}

		try {
			if (errMsgContent.getPKIStatusInfo() != null) {
				if( !errMsg.isEmpty()){
					errMsg += "\n";
				}
				errMsg += "StatusInfo :";
				PKIFreeText freeText = errMsgContent.getPKIStatusInfo().getStatusString();
				for (int i = 0; i < freeText.size(); i++) {
					errMsg += "#" + i + ": " + freeText.getStringAt(i);
				}
			}
		} catch (NullPointerException npe) { // NOSONAR
			// just ignore
		}

		if( !errMsg.isEmpty()){
			log(errMsg);
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
	public static PKMACBuilder getMacCalculatorBuilder() throws CRMFException {

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
	public static MacCalculator getMacCalculator(final String hmacSecret) throws CRMFException {
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

	void warn(String msg){
		LOGGER.warn(msg);
	}

	void log(String msg){
		LOGGER.info(msg);
	}

	void log(String msg, Exception e){
		LOGGER.warn(msg, e);
	}

	void trace(String msg){
		if(cmpClientConfig.isVerbose()) {
//			LOGGER.debug(msg);
			LOGGER.info(msg);
		}
	}

	public class CertificateResponseContent{
		X509Certificate createdCertificate;
		Set<X509Certificate> additionalCertificates = new HashSet<>();
		String message;

		public X509Certificate getCreatedCertificate() {
			return createdCertificate;
		}

		public void setCreatedCertificate(X509Certificate createdCertificate) {
			this.createdCertificate = createdCertificate;
		}

		public Set<X509Certificate> getAdditionalCertificates() {
			return additionalCertificates;
		}

		public void setAdditionalCertificates(Set<X509Certificate> additionalCertificates) {
			this.additionalCertificates = additionalCertificates;
		}

		public String getMessage() {
			return message;
		}

		public void setMessage(String message) {
			this.message = message;
		}
	}
}
