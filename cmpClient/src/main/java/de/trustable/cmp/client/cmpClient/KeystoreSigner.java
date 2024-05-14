package de.trustable.cmp.client.cmpClient;

import de.trustable.cmp.client.ProtectedMessageHandler;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class KeystoreSigner implements ProtectedMessageHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeystoreSigner.class);

    final KeyStore ks;
    final String ksAlias;
    final String ksSecret;


    final boolean ignoreFailedVerification;
    final Certificate signerCertificate;

    public KeystoreSigner(KeyStore ks,
                          String ksAlias,
                          String ksSecret) throws KeyStoreException {
        this(ks, ksAlias, ksSecret, false);
    }
    public KeystoreSigner(KeyStore ks,
                String ksAlias,
                String ksSecret,
        boolean ignoreFailedVerification) throws KeyStoreException {
        this.ks = ks;
        this.ksAlias = ksAlias;
        this.ksSecret = ksSecret;
        this.ignoreFailedVerification = ignoreFailedVerification;

        this.signerCertificate = ks.getCertificate(ksAlias);
    }

    @Override
    public ProtectedPKIMessage signMessage(ProtectedPKIMessageBuilder builder) throws GeneralSecurityException {

        LOGGER.debug("in KeystoreSigner.signMessage using signer '" + ((X509Certificate) signerCertificate).getSubjectDN().getName());

        PrivateKey privKey = (PrivateKey) (ks.getKey(ksAlias, ksSecret.toCharArray()));

        try {
            PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

//			ContentSigner msgsigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
            ContentSigner msgsigner = new JcaContentSignerBuilder("SHA256withRSA/PSS", pssParameterSpec)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(privKey);
            return builder.build(msgsigner);
        } catch (OperatorCreationException | CMPException e) {
            LOGGER.warn("in KeystoreSigner.signMessage", e);
            throw new GeneralSecurityException(e);
        }
    }

    @Override
    public boolean verifyMessage(ProtectedPKIMessage message) throws GeneralSecurityException {

        LOGGER.debug("in KeystoreSigner.verifyMessage ...");

        try {
            if (message.hasPasswordBasedMacProtection()) {
                throw new GeneralSecurityException("Server used MacProtection, but certificate & key present!");
            }
        }catch( Exception ex){
            if(ignoreFailedVerification) {
                LOGGER.info("hasPasswordBasedMacProtection causes exception", ex);
            }else{
                throw ex;
            }
        }

        try {
            X509Certificate certificate = (X509Certificate) (ks.getCertificate(ksAlias));
            ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(certificate);
            return message.verify(verifierProvider);
        } catch (OperatorCreationException | CMPException | KeyStoreException e) {
            if(ignoreFailedVerification) {
                LOGGER.warn("in KeystoreSigner.verifyMessage", e);
                return true;
            }else{
                throw new GeneralSecurityException(e);
            }
        }
    }

    @Override
    public X500Name getSender(X500Name subjectDN) {
        try {
            X509CertificateHolder certificateHolder = new X509CertificateHolder(signerCertificate.getEncoded());
            return certificateHolder.getSubject();
        } catch (IOException | CertificateEncodingException e) {
            LOGGER.info("problem encoding signer certificate", e);
        }
        return subjectDN;
    }

    @Override
    public void addCertificate(ProtectedPKIMessageBuilder pbuilder) {

        try {
            X509CertificateHolder certificateHolder = new X509CertificateHolder(signerCertificate.getEncoded());
            pbuilder.addCMPCertificate(certificateHolder);
            LOGGER.debug("adding protection certificate " + certificateHolder.getSubject());
        } catch (IOException | CertificateEncodingException e) {
            LOGGER.info("problem adding signer certificate", e );
        }
    }

    public KeyStore getKs() {
        return ks;
    }

    public String getKsAlias() {
        return ksAlias;
    }

    public String getKsSecret() {
        return ksSecret;
    }

    public boolean isIgnoreFailedVerification() {
        return ignoreFailedVerification;
    }

}