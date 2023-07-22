package de.trustable.cmp.client.cmpClient;

import de.trustable.cmp.client.ProtectedMessageHandler;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;


class CMPClientImplTest {


    static final String TEST_CSR = "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "MIIE2zCCAsMCAQAwRDELMAkGA1UEBhMCREUxFDASBgNVBAMMC2hvc3QuZGV2ZW52\n" +
            "MR8wHQYDVQQKDBZ0cnVzdGFibGUgc29sdXRpb25zIFVHMIICIjANBgkqhkiG9w0B\n" +
            "AQEFAAOCAg8AMIICCgKCAgEAz2xfb/4zC3dRGRBrFKFyyo23laKogp+8uu4I8yT7\n" +
            "1eVm6dhxnYZkeFFr7Xu3BgEqcL7oQIVRhoH3wAG25B/Y14MGgZWQBklK7CKqL7ZF\n" +
            "EmZnEK5IWSCrj0kHQ9TDW2BM1+gzeSH0Px3Zw94mtkDe02SuIkJyuzrFhQlnMuwC\n" +
            "7RbDMLyKERznZm1/4JyeMV3vCCzjzqISllhFz3sBMvDGUtVSWsdnyiujAh5ysm8d\n" +
            "o1UVpV4DasahW8JE6dDucJmTb2B8J8Ueyhi84xI0Yf8v6UsLKNGvqjlNV9IKj0Bk\n" +
            "O8Drt00H1XOe1L/tniA60sn8o1coB2GecE+cVsT9CN7eAkmdVrJPPLhFCjJT6+nV\n" +
            "CXzVUFSk5xRYVs0bQZsd3lcfnulUEcsb6PCrxyTGW8+DGAOZu0FLZ1nt3cZ3P/4O\n" +
            "wa27YQUvpfR+B0Qh4yxsYesDTRrUwRPr2F1ceo9PkV2+Xxqq9o4zEEqx3mlPLrV4\n" +
            "78iFHfb92iXzh7xxhXs4GYnhYAV0HfOUFAWUwzd67N5DDNdRBLxv7mpCaBErBlNa\n" +
            "+WQ8l5urBo7QYr+Ca9EvZ/g6iW+mGJQcvrTyH+LUqD/VBVc6ESZTWNF/4IzyYD4s\n" +
            "uN5zs5MueDURAbDfZ2UuwFUw1r1N72pNbcVmngsNurvGkxEym55y5Xbtf2l3I14q\n" +
            "380CAwEAAaBSMFAGCSqGSIb3DQEJDjFDMEEwGgYDVR0RBBMwEYIPd3d3Lmhvc3Qu\n" +
            "ZGV2ZW52MA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATANBgkq\n" +
            "hkiG9w0BAQsFAAOCAgEAEijox+CtIX+M5zU8wzfz4lpUTBbXsk2BZMNnR35Hk9wv\n" +
            "1lLfqna6crAZxQ35t08QkDi1spXzJEimibNqjxUOJlM51GUyib0FpLmeg/cIZPNm\n" +
            "2VJgDfqL9Yjqkauo2owFmvQ7eXP0rPnVVSnbi2WuhbWWSkgfhMGfMuZqIiqynV9G\n" +
            "CAOtTrpoAwu/WARr7XO/jzvd/7o6gxLicLhvk/TZfMBiOcs0mXQjl49nOsMMQ28l\n" +
            "oRO1k+j0npft6Rgq2l1o4Y/FLTVLmBAVivwLRAHZjzOukffK3NJjzwH0LbNjFd5g\n" +
            "AnYdwEG9fjupGiEqHg/SAfp7XpxbualyWq6dWEufLJo2W8pkbLtusPsfc9gcxtXq\n" +
            "Z/k8l/2VwNVMB6NISJeJDHYTKwnXUf5dqY/eZn0sDP1l8THi/8tyGaIJTnt4bPIa\n" +
            "mG5fR5HbXRQIteAlg945MaVQmgaTl//DJqBsrmorD66aajaKavgoB5Sten+cJo4B\n" +
            "c/uJELxv+Be5f/LVgK5HjAjG3nwpdt4F8BgAFpxqCVXeZjpy0oyCoMTOU2+V7mot\n" +
            "5vEAgTpZKch0iekdWTVS9haPeXIfCEQ+AH73riOkujxpOMAoVb/ApQGSRBV2knlU\n" +
            "n9PwHgI8HY+TTKbciubS5HOyPWHYLdDgaojQKIatkhqGnjXj12iHc6w1FjihRsc=\n" +
            "-----END CERTIFICATE REQUEST-----";

    CMPClientImpl cmpClient;

    PKCS10CertificationRequest p10TestReq;

    @BeforeEach
    void setUp() throws GeneralSecurityException {


        CMPClientConfig cmpClientConfig = new CMPClientConfig();
        cmpClientConfig.setMultipleMessages(false);
        cmpClient = new CMPClientImpl(cmpClientConfig);

        p10TestReq = cmpClient.convertPemToPKCS10CertificationRequest(new ByteArrayInputStream(TEST_CSR.getBytes()));
    }

    @Test
    void buildCertRequest() throws GeneralSecurityException {

        ProtectedMessageHandler protectedMessageHandler = new DigestSigner("hmacSecret");

        PKIMessage pkiMessage = cmpClient.buildCertRequest(999L,  p10TestReq,  protectedMessageHandler);
        Assertions.assertNotNull(pkiMessage);

        Assertions.assertEquals(2, pkiMessage.getHeader().getPvno().intValueExact());
        Assertions.assertNotNull(pkiMessage.getHeader().getSender());
        Assertions.assertNotNull(pkiMessage.getHeader().getTransactionID());
        Assertions.assertNotNull(pkiMessage.getHeader().getRecipient());

        Assertions.assertEquals(PKIBody.TYPE_CERT_REQ, pkiMessage.getBody().getType());

        CertReqMessages certReqMessages = (CertReqMessages)pkiMessage.getBody().getContent();

        CertReqMsg certReqMsg = certReqMessages.toCertReqMsgArray()[0];

        Assertions.assertNotNull(certReqMsg.getCertReq().getCertTemplate().getExtensions());
        Extensions extensions = certReqMsg.getCertReq().getCertTemplate().getExtensions();
        Extension extensionSAN = extensions.getExtension(Extension.subjectAlternativeName);
        Assertions.assertNotNull(extensionSAN);

        // General Nme 'DNS:www.host.devenv'
        byte[] octets = {48, 17, -126, 15, 119, 119, 119, 46, 104, 111, 115, 116, 46, 100, 101, 118, 101, 110, 118};
        Assertions.assertArrayEquals(octets, extensionSAN.getExtnValue().getOctets());

    }
}