package de.trustable.cmp.client.cmpClient;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

public class PKCS10Generator {


    static PKCS10CertificationRequest getCsr(X500Name x500NameSubject,
        PublicKey pubKey,
        PrivateKey priKey,
        SubjectPublicKeyInfo spkInfoAlt,
        GeneralName[] sanArray)
        throws GeneralSecurityException, IOException {

        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer;
        try {
            signer = signerBuilder.build(priKey);
        } catch (OperatorCreationException e) {
            throw new GeneralSecurityException(e);
        }

        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(
            x500NameSubject, pkInfo);

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

        if (spkInfoAlt != null) {
            JcaX509ExtensionUtils x509ExtensionUtils = new JcaX509ExtensionUtils();

            extensionsGenerator.addExtension(
                Extension.subjectAltPublicKeyInfo, false,
                x509ExtensionUtils.createSubjectKeyIdentifier(spkInfoAlt));
        }

        if (sanArray != null) {
            GeneralNames subjectAltNames = new GeneralNames(sanArray);
            extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
            System.out.println("added #" + sanArray.length + " sans");
            for (GeneralName gn : sanArray) {
                System.out.println("san :" + gn);
            }
        }

        if( !extensionsGenerator.isEmpty()) {
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        }

        return builder.build(signer);
    }

}
