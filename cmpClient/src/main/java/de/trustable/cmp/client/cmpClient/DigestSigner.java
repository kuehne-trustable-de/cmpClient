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

import java.security.GeneralSecurityException;

public class DigestSigner implements ProtectedMessageHandler {

    final private char[] hmacSecret;

    public DigestSigner(String hmacSecret) {

        this.hmacSecret = hmacSecret.toCharArray();
    }

    @Override
    public ProtectedPKIMessage signMessage(ProtectedPKIMessageBuilder builder) throws GeneralSecurityException {
        System.out.println("in DigestSigner.signMessage ...");
        try {
            MacCalculator macCalculator = getMacCalculator(hmacSecret);
            return builder.build(macCalculator);
        } catch (CRMFException | CMPException e) {
            throw new GeneralSecurityException(e);
        }
    }

    @Override
    public boolean verifyMessage(ProtectedPKIMessage message) throws GeneralSecurityException {
        System.out.println("in DigestSigner.verifyMessage ...");

        if (!message.hasPasswordBasedMacProtection()) {
            throw new GeneralSecurityException("HMAC secret present, bt server did NOT use MacProtection!");
        }

        try {
            return message.verify(getMacCalculatorBuilder(), hmacSecret);
        } catch (CMPException | CRMFException e) {
            throw new GeneralSecurityException(e);
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

}
