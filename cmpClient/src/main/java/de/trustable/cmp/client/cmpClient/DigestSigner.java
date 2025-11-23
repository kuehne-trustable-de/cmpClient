package de.trustable.cmp.client.cmpClient;

import de.trustable.cmp.client.ProtectedMessageHandler;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.operator.MacCalculator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;

public class DigestSigner implements ProtectedMessageHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(DigestSigner.class);

    final private char[] hmacSecret;
    final private boolean ignoreFailedVerification;

    public DigestSigner(String hmacSecret) {
        this(hmacSecret, false);
    }

    public DigestSigner(String hmacSecret, boolean ignoreFailedVerification) {

        this.hmacSecret = hmacSecret.toCharArray();
        this.ignoreFailedVerification = ignoreFailedVerification;
    }

    @Override
    public ProtectedPKIMessage signMessage(ProtectedPKIMessageBuilder builder) throws GeneralSecurityException {
        LOGGER.debug("in DigestSigner.signMessage ...");
        try {
            MacCalculator macCalculator = getMacCalculator(hmacSecret);
            return builder.build(macCalculator);
        } catch (CRMFException | CMPException e) {
            throw new GeneralSecurityException(e);
        }
    }

    @Override
    public boolean verifyMessage(ProtectedPKIMessage message) throws GeneralSecurityException {
        LOGGER.debug("in DigestSigner.verifyMessage ...");

        if (!message.hasPasswordBasedMacProtection()) {
            if(ignoreFailedVerification){
                LOGGER.info("HMAC secret present, but server did NOT use MacProtection!");
            }else {
                throw new GeneralSecurityException("HMAC secret present, but server did NOT use MacProtection!");
            }
        }

        try {
            return message.verify(getMacCalculatorBuilder(), hmacSecret);
        } catch (CMPException | CRMFException e) {
            if(ignoreFailedVerification){
                LOGGER.info("HMAC verification failed, but ignoring it!", e);
                return true;
            }else {
                throw new GeneralSecurityException(e);
            }
        }
    }

    @Override
    public X500Name getSender(X500Name subjectDN) {
        return subjectDN;
    }

    @Override
    public void addCertificate(ProtectedPKIMessageBuilder pbuilder) {
        // nothing to do ...
    }

    /**
     * build a HMAC  calculator from a given secret
     *
     * @param hmacSecret the given secret for this connection
     * @return the HMACCalculator object
     * @throws CRMFException creation of the calculator failed
     */
    public static MacCalculator getMacCalculator(final char[] hmacSecret) throws CRMFException {
        PKMACBuilder macbuilder = getMacCalculatorBuilder();
        return macbuilder.build(hmacSecret);
    }

    /**
     * build a PKMACBuilder
     *
     * @return the PKMACBuilder object withdefault algorithms
     * @throws CRMFException creation of the calculator failed
     */
    public static PKMACBuilder getMacCalculatorBuilder() throws CRMFException {

        JcePKMACValuesCalculator jcePkmacCalc = new JcePKMACValuesCalculator();
        final AlgorithmIdentifier digAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26")); // SHA1
        final AlgorithmIdentifier macAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.2.7")); // HMAC/SHA1
        jcePkmacCalc.setup(digAlg, macAlg);
        return new PKMACBuilder(jcePkmacCalc);
    }

}
