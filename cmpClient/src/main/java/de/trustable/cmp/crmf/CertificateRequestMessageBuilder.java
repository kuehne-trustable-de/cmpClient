package de.trustable.cmp.crmf;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;

import java.math.BigInteger;

public class CertificateRequestMessageBuilder
{
    private final BigInteger certReqId;

    private final ExtensionsGenerator extGenerator;
    private final CertTemplateBuilder templateBuilder;
    private ASN1Null popRaVerified;

    private AttributeTypeAndValue[] attributeTypeAndValues;

    public CertificateRequestMessageBuilder(BigInteger certReqId)
    {
        this.certReqId = certReqId;

        this.extGenerator = new ExtensionsGenerator();
        this.templateBuilder = new CertTemplateBuilder();
        this.attributeTypeAndValues = new AttributeTypeAndValue[0];
    }

    public void setAttributeTypeAndValues(AttributeTypeAndValue[] attributeTypeAndValues) {
        this.attributeTypeAndValues = attributeTypeAndValues;
    }


    //
    public CertificateRequestMessageBuilder setPublicKey(SubjectPublicKeyInfo publicKey)
    {
        if (publicKey != null)
        {
            templateBuilder.setPublicKey(publicKey);
        }

        return this;
    }

    //
    public CertificateRequestMessageBuilder setIssuer(X500Name issuer)
    {
        if (issuer != null)
        {
            templateBuilder.setIssuer(issuer);
        }

        return this;
    }

//
    public CertificateRequestMessageBuilder setSubject(X500Name subject)
    {
        if (subject != null)
        {
            templateBuilder.setSubject(subject);
        }

        return this;
    }



    //
    public CertificateRequestMessageBuilder addExtension(
        ASN1ObjectIdentifier oid,
        boolean              critical,
        byte[]               value)
    {
        extGenerator.addExtension(oid, critical, value);

        return this;
    }


    //
    public CertificateRequestMessageBuilder setProofOfPossessionRaVerified()
    {
        this.popRaVerified = DERNull.INSTANCE;
        return this;
    }

    public CertificateRequestMessage build()
        throws CRMFException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(certReqId));

        if (!extGenerator.isEmpty())
        {
            templateBuilder.setExtensions(extGenerator.generate());
        }

        v.add(templateBuilder.build());


        CertRequest request = CertRequest.getInstance(new DERSequence(v));

        v = new ASN1EncodableVector();

        v.add(request);


        if (popRaVerified != null)
        {
            v.add(new ProofOfPossession());
        }

        CertReqMsg certReqMsg = new CertReqMsg(request, new ProofOfPossession(), attributeTypeAndValues);

        return new CertificateRequestMessage(certReqMsg);
    }
}