package de.trustable.cmp.client.cmpClient;

import de.trustable.cmp.client.ProtectedMessageHandler;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIMessages;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Base64;


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

//    static final String TEST_PKI_MESSAGES ="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";
//    static final String TEST_CMP_CERT_RESPONSE = "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";

    static final String TEST_PKI_MESSAGES ="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";
    static final String TEST_CMP_CERT_RESPONSE = "MIIa8zCCGu8weQIBAqQgMB4xHDAaBgNVBAMTE1JlZi1DU00gU2VydmVyLVNpZ26kAjAApCIEIHRyYW5zYWN0aW9uSWQ3ODkzNzQ0OTI2MTEyODAyMzczphoEGG5vbmNlNzg5Mzc0NDkyNjExMjgwMjM3M6gOMAwwCgYIKwYBBQUHBA2jghF4MIIRdKGCCjwwggo4MIIFzDCCBLSgAwIBAgIDD+VHMA0GCSqGSIb3DQEBCwUAMFgxCzAJBgNVBAYTAkRFMRUwEwYDVQQKDAxELVRydXN0IEdtYkgxMjAwBgNVBAMMKUQtVFJVU1QgTGltaXRlZCBCYXNpYyBSb290IFRlc3QgQ0EgMSAyMDE5MB4XDTE5MDgxNTA4MjYyN1oXDTM0MDYxOTA4MzU1MVowVTELMAkGA1UEBhMCREUxFTATBgNVBAoMDEQtVHJ1c3QgR21iSDEvMC0GA1UEAwwmRC1UUlVTVCBMaW1pdGVkIEJhc2ljIFRlc3QgQ0EgMS0yIDIwMTkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCg1VOYlgKbXtDK1MC3CAO52YM6rdPbUxtrxYyKfdK/8EreUMP2ywezLKIkL/Q3WpAtcORPbugoRzeGs5AH9UgkBpvj3XXtEw0ApM9ovdoBm/kr9tI37nbxyihE4rZhydOzwTB7hSYRe2iCukq0/dN/tUCEU/HIg3MpgpdL/3Ng1qZmMQtAV/cuHOeggoSfatIflCrnZKB3frNGWpNFBD3/Hh8tn14UDwIDY4xp864HFldZdoZoarB7aehZmP2r1BqeEIyXHPFaDt5RNCDEIom33m/fJxJDwJmHk9NMBQClKwdpZFY/DYCbhzyZ3OLi7s9meuxLb/7jXSoiBvSX3VoLAgMBAAGjggKgMIICnDAfBgNVHSMEGDAWgBT6gZK81LFNmRoE1gqhN9bxPX6etzCCASoGCCsGAQUFBwEBBIIBHDCCARgwKwYIKwYBBQUHMAGGH2h0dHA6Ly9zdGFnaW5nLm9jc3AuZC10cnVzdC5uZXQwWAYIKwYBBQUHMAKGTGh0dHA6Ly93d3cuZC10cnVzdC5uZXQvY2dpLWJpbi9ELVRSVVNUX0xpbWl0ZWRfQmFzaWNfUm9vdF9UZXN0X0NBXzFfMjAxOS5jcnQwgY4GCCsGAQUFBzAChoGBbGRhcDovL2RpcmVjdG9yeS5kLXRydXN0Lm5ldC9DTj1ELVRSVVNUJTIwTGltaXRlZCUyMEJhc2ljJTIwUm9vdCUyMFRlc3QlMjBDQSUyMDElMjAyMDE5LE89RC1UcnVzdCUyMEdtYkgsQz1ERT9jQUNlcnRpZmljYXRlP2Jhc2U/MBcGA1UdIAQQMA4wDAYKKwYBBAGlNAICAjCB7gYDVR0fBIHmMIHjMIGQoIGNoIGKhoGHbGRhcDovL2RpcmVjdG9yeS5kLXRydXN0Lm5ldC9DTj1ELVRSVVNUJTIwTGltaXRlZCUyMEJhc2ljJTIwUm9vdCUyMFRlc3QlMjBDQSUyMDElMjAyMDE5LE89RC1UcnVzdCUyMEdtYkgsQz1ERT9jZXJ0aWZpY2F0ZXJldm9jYXRpb25saXN0ME6gTKBKhkhodHRwOi8vY3JsLmQtdHJ1c3QubmV0L2NybC9kLXRydXN0X2xpbWl0ZWRfYmFzaWNfcm9vdF90ZXN0X2NhXzFfMjAxOS5jcmwwHQYDVR0OBBYEFBVkOhPASZBJUZL69PGVC2l4Kp51MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQBv3/u8dPMB6AjgTuy41NPOtQ+VMzV+DY5bjxZzh/P1VfcLutII41ia3wZ14Aol01abSek7nXVvKXN9mc2Mw79WIcGceDNvHsGyRabpMtowb92LOyfx/F9uj6Guv+Bh9N0U26lYPZOq/TMcfYMTmxlIZOqMOqt5m3oqTiGLjvw4s+UCtCmOYujnpQakqjfxHCr7Q3YGTtS6WhimAFG9dWj1OPW0DncWikjRrYHetE2WUnrH/RU6XXrKQYcc9wekoJx3czBZVGvUsjF/v+LCwvcMzxvtKrVOnMLmbY8Q7/q++J0kSrkUQz6IMr+Gjr33EdZ1drELYV9HcDd2xhO+lV8oMIIEZDCCA0ygAwIBAgIDD+UqMA0GCSqGSIb3DQEBCwUAMFgxCzAJBgNVBAYTAkRFMRUwEwYDVQQKDAxELVRydXN0IEdtYkgxMjAwBgNVBAMMKUQtVFJVU1QgTGltaXRlZCBCYXNpYyBSb290IFRlc3QgQ0EgMSAyMDE5MB4XDTE5MDYxOTA4MzU1MVoXDTM0MDYxOTA4MzU1MVowWDELMAkGA1UEBhMCREUxFTATBgNVBAoMDEQtVHJ1c3QgR21iSDEyMDAGA1UEAwwpRC1UUlVTVCBMaW1pdGVkIEJhc2ljIFJvb3QgVGVzdCBDQSAxIDIwMTkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC53b4+X3MIn4SEaFIKmUjZGo/9lBGXOUxtqxQHv5cqOo27KI1ZwrxBQAdUlOtPbRhWG6ei8MC8HN5QQfhI3V21KVb5z9pVkgspotdY8YuxnqtuXHxwlii/WxgxapyWs42tFLS8C+achO6qVlNoDOmVkeOETxvYwMITq6XhA4qZ+tnnGg08i1CRaADWXmUzFzfq2Rtt1e2jUKqP1+844uuXQA88yaaLbEmGH414H06Jbkfv9XQD/a9egBWHLfsiahxjh0X8D9cV4bBuGMzY3N3PtZ8xDhPc1OMlI5v8cSTbyL69brb09cge18G1pDLwW9hMGqIkwDmONvnGTv2ngSBLAgMBAAGjggE1MIIBMTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBT6gZK81LFNmRoE1gqhN9bxPX6etzAOBgNVHQ8BAf8EBAMCAQYwge4GA1UdHwSB5jCB4zCBkKCBjaCBioaBh2xkYXA6Ly9kaXJlY3RvcnkuZC10cnVzdC5uZXQvQ049RC1UUlVTVCUyMExpbWl0ZWQlMjBCYXNpYyUyMFJvb3QlMjBUZXN0JTIwQ0ElMjAxJTIwMjAxOSxPPUQtVHJ1c3QlMjBHbWJILEM9REU/Y2VydGlmaWNhdGVyZXZvY2F0aW9ubGlzdDBOoEygSoZIaHR0cDovL2NybC5kLXRydXN0Lm5ldC9jcmwvZC10cnVzdF9saW1pdGVkX2Jhc2ljX3Jvb3RfdGVzdF9jYV8xXzIwMTkuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQAGUHjpwGXFN+nDHEp1c/Fus6cHQaIU5llDvXPXHZnqOigGPGKs7HTktCbJrvAmd0M3u/ZlgRHYYyoYltIH4hYo663yPXd845+l8ym3kQZq4opcTHiNpR2feGegAxCt41jQSiqTBRLqIvNPB0DQ8wTsRSNJnzT4mvaUzUNNH6yBIBa/7YWHx4lmK2UCfRkOBdwSmA31cutaovUhaBZeviQ9fjyUI2porLEepxbV8CYOI4UEikXI0/eLwCguh+qoKI/UpOP9exCSjjOzc5iOZgfblNWh+Z6WdDK6J2z+0DHVnYLz9yj06U7q5/OQfisbpTbgvEFcasc0ItwqVeD/z0YeMIIHMDCCBywCCIpCPIw0CqGtMAMCAQAwggcZoIIHFTCCBxEwggX5oAMCAQICEHHvxDNQmuBhFI6zp65HJCIwDQYJKoZIhvcNAQELBQAwVTELMAkGA1UEBhMCREUxFTATBgNVBAoMDEQtVHJ1c3QgR21iSDEvMC0GA1UEAwwmRC1UUlVTVCBMaW1pdGVkIEJhc2ljIFRlc3QgQ0EgMS0yIDIwMTkwHhcNMjQwMjE5MjE1NDI4WhcNMjUwMjIyMjE1NDI4WjB3MRUwEwYDVQQFEwxDU00wMjcyMzcxMzMxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIEwZCZXJsaW4xDzANBgNVBAcTBkJlcmxpbjEMMAoGA1UEChMDQktBMSEwHwYDVQQDExhjbXB0ZXN0LmNhM3MuYmthLmJ1bmQuZGUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCcb0f/yr7k0aEpGQwL2cH/3UdgPjUmq/SEOnlLy+MF0/wBvu3CPdNsmVbuxIDLSiAYmA5hUKeaYB1F3jl8ftT4VvZk0L4xoEczkS3I8UDMud0ieBIH7VcXygenOAIsVwUdh9+y9i9if0C5NXPUPyjoLL4PX6zyEjvFX5/p4/Yej9kokF2fPgaf7wNqloZplvoupjXGfOrcBmGdue4MkEVtoxq99vAFal9PAhWEr3yTkNc07VK7VduHC0UxrwLnEV0+UYi+uUHSt8cAUIYx4+mBPQnpi92TCHPInbSGqFCnsEJnc/ArlqjMSPia9y6a6/Mf5mOtEdzwk7ZLowdXHtD4BMhru0k5m7bZ49MW2I1iKpS9ajvTg2vTrtlGF5HJ11c05EOSr86eZoP/tyFMPJE9+GnmYsNFS5dp+C39Qzzp3oZgiLu3Z+F9+GVdrv6tVnfaBZzzrJ9Byda6oJ5IV3fu53uUZtNgU0DeqFPEsVcW2WijMbkvS9BtHfMcX+4DCxEPp02+DFqethVy/AZT5Ibjf+9XMxt5jn0BVZfn4wfP27ySyMvPWrOrXfguPSh40pu5P8cog7QwgxuWKESqCB9UiarmZGk7oYMbspsnMKLGiT1g5duvaaHgiu6UB72EUIId54+nuxRwhfZF6BE8ZEBUIQ0BqDSklnVOQ3yB3qr5mwIDAQABo4ICuTCCArUwggEhBggrBgEFBQcBAQSCARMwggEPMCsGCCsGAQUFBzABhh9odHRwOi8vc3RhZ2luZy5vY3NwLmQtdHJ1c3QubmV0MFUGCCsGAQUFBzAChklodHRwOi8vd3d3LmQtdHJ1c3QubmV0L2NnaS1iaW4vRC1UUlVTVF9MaW1pdGVkX0Jhc2ljX1Rlc3RfQ0FfMS0yXzIwMTkuY3J0MIGIBggrBgEFBQcwAoZ8bGRhcDovL2RpcmVjdG9yeS5kLXRydXN0Lm5ldC9DTj1ELVRSVVNUJTIwTGltaXRlZCUyMEJhc2ljJTIwVGVzdCUyMENBJTIwMS0yJTIwMjAxOSxPPUQtVHJ1c3QlMjBHbWJILEM9REU/Y0FDZXJ0aWZpY2F0ZT9iYXNlPzAXBgNVHSAEEDAOMAwGCisGAQQBpTQCAgIwgeAGA1UdHwSB2DCB1TCB0qCBz6CBzIZFaHR0cDovL2NybC5kLXRydXN0Lm5ldC9jcmwvZC10cnVzdF9saW1pdGVkX2Jhc2ljX3Rlc3RfY2FfMS0yXzIwMTkuY3JshoGCbGRhcDovL2RpcmVjdG9yeS5kLXRydXN0Lm5ldC9DTj1ELVRSVVNUJTIwTGltaXRlZCUyMEJhc2ljJTIwVGVzdCUyMENBJTIwMS0yJTIwMjAxOSxPPUQtVHJ1c3QlMjBHbWJILEM9REU/Y2VydGlmaWNhdGVyZXZvY2F0aW9ubGlzdDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwIwYDVR0RBBwwGoIYY21wdGVzdC5jYTNzLmJrYS5idW5kLmRlMB8GA1UdIwQYMBaAFBVkOhPASZBJUZL69PGVC2l4Kp51MA4GA1UdDwEB/wQEAwIFoDAdBgNVHQ4EFgQUOr2efLkbqudJNGXLNjLSuOzDkY0wDQYJKoZIhvcNAQELBQADggEBAEX+gtOV3VL5Im+PLOdJWFBsKwakPYplhmaqBljEzcU+vGA+zdKuuYAqufrO1ljBOI7joI1pJV39kZSNYtNezAUv5etTu+U93/pcSTrTB6MqZSn7aoBRrLV1YJqTaKxALxxEReyCmOOt3PU8lA/z94ChO1YlXHszEaGi+GfAYjIjACPPgXrekD+eeW9bSVSRHZNlDFdjrMED1YEoDFSRLmFWwGvKvZV5QZ0DFe6hd8wkxDCckFtiOJVg9pCqESa0wJHc60goW6HloiRzpyj5Z6vwJsQcfCCTLKGbs6GeLbciO4avTwM1VYU7nvMUGFmdRuVimUemaGcXs151HuMWufugggIFA4ICAQDNkVvf7KDNr+acqa2rOZQ4bfFpMYF0tpJgjzq78JNRO2VsaqVnw1nTJYa27FXBjbfNGPUbD6hM2bL6SK3ZzKumLKaGUN8qjJy6fi02IbKu+cboI1UjTzbs4DkAgSpG4pVBSo3lBVOPLq2qVmT1aBTVQEGrYpALRGkDsIDIOAtVbCa/Au4tvxnm6edjETfsHCV9kVmGOXscvSGMbzDkXy+6bv09rxYLzCfi/ABfTwlxZORH8gG3iuIs1c76X7inkq0NcTDQd5CGKhs2i6294H3K61CVdifPy+otTYyIv+v2Mx4Sajw2mTg7rO41qXmI0Ur0keSeIZbBix9DcurxJI8JEmfTiOL1FFk/w1ofoP6Xnida8IpO0LosKS3DNzhAfi0T1qsybtHprM9xtZ8bukDNour1t+q19o+mpoR5IOQFLUdi1FT9V2uvy6o9RnktIM0PlNOvpo470aSTAyVhjx6IXFrc6zWqkKRdUHSqY0yu8RHVPAIJaNKWnxOihUR9QGM+rGAP9dqXHhr/kfju4nVurn3s5zMO2aNH/uOCo3bZfuEpFprlk6UbqoMClE3woCqkmgGyQOL6CXHg0ZEOMOu1iMDIFNIAyTF2BmKJg2MPhbYq4ffFnsVqszPqJdWxn0kmqN1jFPR4p7upVPaQiQsGZx13VF2Kdy2KnHtx5B+8gaGCBuswggbnMIIG4zCCBcugAwIBAgIQW053tzdWVEg3AMXZ8xTTvDANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJERTEVMBMGA1UECgwMRC1UcnVzdCBHbWJIMSowKAYDVQQDDCFELVRSVVNUIExpbWl0ZWQgQmFzaWMgQ0EgMS0yIDIwMTkwHhcNMjExMjIxMTUxODIxWhcNMjQxMjI2MTUxODIxWjB7MQswCQYDVQQGEwJERTEVMBMGA1UEChMMRC1UcnVzdCBHbWJIMRwwGgYDVQQDExNSZWYtQ1NNIFNlcnZlci1TaWduMQ8wDQYDVQQHEwZCZXJsaW4xFTATBgNVBAUTDENTTTAyODU2MDEwODEPMA0GA1UECBMGQmVybGluMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA536dqlNQMPrq1C1tr9yXWbKIangaCGoxw7QeDR4GqIi1WmshwA3aXCOktw31cJ4plrBVLvTJK8FhJfB6mQOuLMrPRsHhQ3FvAbzvoA0vLSUKEUlTVmnbx0BgFG5Op9kPvc90Qws5GWujOoIvnoC+LTSq1zpwU9nOwJPbaFChUU8wm6lfMlvIRR1mhrM4uGD206K5RDSIFEkv2YEyd+MXPUqu9L+8hTKNq+7e2pinOaKqRwhXq4ceozBfY+SeTKXE1tnS7GFGrc3Rm0OIKuXBN8M1CkKm+n2LDsSENUVSFBfQracGaxBUmfHO8KkzrGJy883AQIXqSanFR9YPrEyDNskuiHvwUu1VL9EyCNygVrMv+N8AdC50At2eOeYyGOKBk500kbBwWNfPIAfVrvg1+PcqdhzZSfjJS6sE38V4DSF20v/CdarnRgJRYUsMOXnSKfBmtw+sfRMj5pRq3KQ0nwiXjzs8BvY3aucBNnKBwTPq1ZyclZ4EzoR0OOzGA8Px1uhXigri0ajL/gNZrlqiLaoz7WBcvfaCMSTRIln+9xBRjPDYEwVIO0v6zWGdlwOM2DFnkl3HLtGSUiWL7+JmY5lHZrK0ZE/gRvMNNoYO7qk9HdSLV4C2wNt+YDuCUImimnx7LDy4RmB4mSlnlSyHvA6R04PSXBDzOCD16jlfpmMCAwEAAaOCAowwggKIMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFNANPtwIr+NBCGbg3PL6mWot3xi5MIIBLwYIKwYBBQUHAQEEggEhMIIBHTBFBggrBgEFBQcwAYY5aHR0cDovL2QtdHJ1c3QtbGltaXRlZC1iYXNpYy1jYS0xLTItMjAxOS5vY3NwLmQtdHJ1c3QubmV0MFAGCCsGAQUFBzAChkRodHRwOi8vd3d3LmQtdHJ1c3QubmV0L2NnaS1iaW4vRC1UUlVTVF9MaW1pdGVkX0Jhc2ljX0NBXzEtMl8yMDE5LmNydDCBgQYIKwYBBQUHMAKGdWxkYXA6Ly9kaXJlY3RvcnkuZC10cnVzdC5uZXQvQ049RC1UUlVTVCUyMExpbWl0ZWQlMjBCYXNpYyUyMENBJTIwMS0yJTIwMjAxOSxPPUQtVHJ1c3QlMjBHbWJILEM9REU/Y0FDZXJ0aWZpY2F0ZT9iYXNlPzAYBgNVHSAEETAPMA0GCysGAQQBpTQCg3QBMIHTBgNVHR8EgcswgcgwgcWggcKggb+GQGh0dHA6Ly9jcmwuZC10cnVzdC5uZXQvY3JsL2QtdHJ1c3RfbGltaXRlZF9iYXNpY19jYV8xLTJfMjAxOS5jcmyGe2xkYXA6Ly9kaXJlY3RvcnkuZC10cnVzdC5uZXQvQ049RC1UUlVTVCUyMExpbWl0ZWQlMjBCYXNpYyUyMENBJTIwMS0yJTIwMjAxOSxPPUQtVHJ1c3QlMjBHbWJILEM9REU/Y2VydGlmaWNhdGVyZXZvY2F0aW9ubGlzdDAdBgNVHQ4EFgQUgDvWoJsx7f5W2HP4deB2sYkUGxYwDgYDVR0PAQH/BAQDAgSwMA0GCSqGSIb3DQEBCwUAA4IBAQABoMfKlGaObvUemqPV/PDw6oIqsEcw7Eu2mC12WxdEUxI4oUxTISV14fUgPPpqmFxxNArXIS+hYDEXLiEIV3iPuq5sTOPPjtI8qdRMiOvpSqdKJ/WHInTnPQFln4PdLYwml40J2P781xHFiYt5RSS1BJQjMfa9dJ4PvlyY52hTjDSkncmiONRwHjIaLmd/QZ+anMxXfGiyrGtv4BPSBBW3Ux6P3o7SDrMKWOKVrQm2a0YmXjNW8hbgCYeTCIu8UJflBZ4JvoXGBnQOevQOLVUsSoMmU5w/wm1qzulWN3EP5pZuHSsTy7xBMzFRHIgCudbpUv32Bm/m9s8lu7d3YeWj";

    static final String TEST_CMP_ERR_REQUEST ="MIID0DCCAR0CAQKkTjBMMQswCQYDVQQGEwJERTEUMBIGA1UEAwwLZm9vLmJhci5iYXoxJzAlBgkqhkiG9w0BCQEWGGZvby5iYXIuYmF6QHRydXN0YWJsZS5kZaQCMACgERgPMjAyNDA1MDUxMzA3NDZaoUAwPgYJKoZIhvZ9B0INMDEEFDAp5WzDnBF5LNEjSfI8hOryXNu4MAcGBSsOAwIaAgID6DAMBggrBgEFBQgBAgUAohsEGWtleUlkLTUxMzI2MzkyNDM3MDAwMzY1NjakIwQhdHJhbnNhY3Rpb25JZC01MTMyNjM5MjQzNzAwMDM2NTY2pRsEGW5vbmNlLTUxMzI2MzkyNDM3MDAwMzY1NjaoEDAOMAwGCCsGAQUFBwQNBQCiggKSMIICjjCCAoowggKEAghAxiAMkKfsNTCCAnalTjBMMQswCQYDVQQGEwJERTEUMBIGA1UEAwwLZm9vLmJhci5iYXoxJzAlBgkqhkiG9w0BCQEWGGZvby5iYXIuYmF6QHRydXN0YWJsZS5kZaaCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMIoNXJr16qgi/TdZsZNDLUvmef/afzgwDS2HOe08/hJQ53lQcY4wFW+JNIvoaoHZFfnXgQiimENM3Q47IUSjx9j9+6qK7aHq6rTG4Pcqlc5yUfbHbX0YWAsFG9M9dzYH9uq4SIE5pzUM1JAWOMZ86hsNB1tGn9bVsx4XF+o8ujDPIkhYB+jH38rN0NrGWEDtMZYpP6/envDC8byHBF5XwZhTWW58iMyF/8k0AlpBjAnthzhulxI8ABpCT0gwYOygYGlXINC4WCf6B8lBsM0gUibE+Lmzle96rcYkPTjNiRMP2Mdpe9jWxPH54t4V1mLa8pxCy4b3FfFDRiyE1AvNg1hfdVZwOeihlApJiZ0qpkiuJHxpiIkVJjvoKAu+z7YxFXr8UeUFktED42FTv1FZGNfeZGxRfWDbsKDQ5bEG+kyxOddg6GX1+OK0offwiHXp1zyucAnCW86axhqyITAKs25elxmZMGdd3FvHW1pGYW4e6EENy6Q3xWoPDpEg5kX9yyBbqGI8XdkiX3S4tkK/DLMqFvjJumWhPfnziGKzNVfKJxk0rzs8ikRtteFQgb1/9SMGr1Df3VwM65Y3fF61TIDbJWiu+z571TYrpZqPjaKjS93Azobiu6FaBiSKSuc1AGjN6ugn5p4nczQDh9heP8JXt/MCABy4oFNwKyc1XyzAgMBAAGAAKAXAxUAGyTUmunWmarrudF+8ZU0OywUnFg=";

    static final String TEST_CMP_ERR_RESPONSE = "MIIBLTCBwAIBAqQCMACkTjBMMQswCQYDVQQGEwJERTEUMBIGA1UEAwwLZm9vLmJhci5iYXoxJzAlBgkqhkiG9w0BCQEWGGZvby5iYXIuYmF6QHRydXN0YWJsZS5kZaARGA8yMDI0MDUwNTEzMDgwMFqkIwQhdHJhbnNhY3Rpb25JZC01MTMyNjM5MjQzNzAwMDM2NTY2pRIEEMpS1vFHiBUCK7YktMxPGs6mGwQZbm9uY2UtNTEzMjYzOTI0MzcwMDAzNjU2NrdoMGYwZAIBAjBbDFlGYWlsZWQgdG8gdmVyaWZ5IG1lc3NhZ2UgdXNpbmcgYm90aCBHbG9iYWwgU2hhcmVkIFNlY3JldCBhbmQgQ01QIFJBIEF1dGhlbnRpY2F0aW9uIFNlY3JldAMCBSA=";

    CMPClientImpl cmpClient;

    PKCS10CertificationRequest p10TestReq;

    @BeforeEach
    void setUp() throws GeneralSecurityException {


        ProtectedMessageHandler messageHandler = new ProtectedMessageHandler(){
            @Override
            public ProtectedPKIMessage signMessage(ProtectedPKIMessageBuilder builder) throws GeneralSecurityException {
                return null;
            }

            @Override
            public boolean verifyMessage(ProtectedPKIMessage message) throws GeneralSecurityException {
                return true;
            }

            @Override
            public X500Name getSender(X500Name subjectDN) {
                return null;
            }

            @Override
            public void addCertificate(ProtectedPKIMessageBuilder pbuilder) {

            }
        };

        CMPClientConfig cmpClientConfig = new CMPClientConfig();
        cmpClientConfig.setMultipleMessages(false);
        cmpClientConfig.setMessageHandler(messageHandler);
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

    @Test
    void parseCertRequest() throws GeneralSecurityException, IOException, CMPException, CRMFException {

        final ASN1Primitive derObject = cmpClient.getDERObject(Base64.getDecoder().decode(TEST_PKI_MESSAGES));

        final PKIMessages pkiMessages = PKIMessages.getInstance(derObject);
        PKIMessage[] pkiMessageArr = pkiMessages.toPKIMessageArray();
        CMPClientImpl.CertificateResponseContent certificateResponseContent = cmpClient.readCertResponse(Base64.getDecoder().decode( TEST_CMP_CERT_RESPONSE), pkiMessageArr[0]);

        Assertions.assertNotNull(certificateResponseContent);
        Assertions.assertNotNull(certificateResponseContent.getCreatedCertificate());

        Assertions.assertNotNull(certificateResponseContent.getAdditionalCertificates());
        Assertions.assertEquals(3, certificateResponseContent.getAdditionalCertificates().size());

        Assertions.assertNotNull(certificateResponseContent.getMessage());
        Assertions.assertEquals("", certificateResponseContent.getMessage());
    }
    @Test
    void validateCertRequestKeySigner() throws GeneralSecurityException, IOException, CMPException, CRMFException {

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(this.getClass().getResourceAsStream("tenant.foo.com.p12"),"S3cr3t!S".toCharArray());
        KeystoreSigner keystoreSigner = new KeystoreSigner(ks,
                "alias",
                "S3cr3t!S",
                true);

        PKIMessage pkiMessage = cmpClient.getPkiMessage(Base64.getDecoder().decode(TEST_CMP_CERT_RESPONSE));

        ProtectedPKIMessage protectedPKIMsg = new ProtectedPKIMessage(new GeneralPKIMessage(pkiMessage));

        keystoreSigner.verifyMessage(protectedPKIMsg);

    }

    @Test
    void parseCertErrResponse() throws GeneralSecurityException, IOException, CMPException, CRMFException {

        final ASN1Primitive derObject = cmpClient.getDERObject(Base64.getDecoder().decode(TEST_CMP_ERR_REQUEST ));

        PKIMessage.getInstance(derObject);

        final PKIMessage pkiMessage = PKIMessage.getInstance(derObject);
        try {
            CMPClientImpl.CertificateResponseContent certificateResponseContent = cmpClient.readCertResponse(Base64.getDecoder().decode(TEST_CMP_ERR_RESPONSE), pkiMessage);
            Assertions.fail("Expecting a GeneralSecurityException on erroer response");
        } catch(GeneralSecurityException ge){
            Assertions.assertEquals( "StatusInfo :#0: Failed to verify message using both Global Shared Secret and CMP RA Authentication Secret", ge.getMessage());
        }
    }




}