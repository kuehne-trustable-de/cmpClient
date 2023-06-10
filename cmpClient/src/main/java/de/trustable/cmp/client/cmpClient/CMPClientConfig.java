package de.trustable.cmp.client.cmpClient;

import de.trustable.cmp.client.ProtectedMessageHandler;
import de.trustable.cmp.client.RemoteTargetHandler;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;

import java.security.KeyStore;

public class CMPClientConfig {

    private boolean implicitConfirm = true;
    private ProtectedMessageHandler messageHandler = null;

    private RemoteTargetHandler remoteTargetHandler;

    private KeyStore p12ClientStore = null;
    private String p12ClientSecret = "";
    private String caUrl = "http://...,";
    private String cmpAlias = "test";
    private X500Name issuerName = null;
    private AttributeTypeAndValue[] aTaVArr = new AttributeTypeAndValue[0];
    private boolean multipleMessages = true;
    private boolean checkTransactionIdMatch = false;
    private boolean verbose = false;

    public boolean isImplicitConfirm() {
        return implicitConfirm;
    }

    public void setImplicitConfirm(boolean implicitConfirm) {
        this.implicitConfirm = implicitConfirm;
    }

    public ProtectedMessageHandler getMessageHandler() {
        return messageHandler;
    }

    public void setMessageHandler(ProtectedMessageHandler messageHandler) {
        this.messageHandler = messageHandler;
    }

    public RemoteTargetHandler getRemoteTargetHandler() {
        return remoteTargetHandler;
    }

    public void setRemoteTargetHandler(RemoteTargetHandler remoteTargetHandler) {
        this.remoteTargetHandler = remoteTargetHandler;
    }

    public KeyStore getP12ClientStore() {
        return p12ClientStore;
    }

    public void setP12ClientStore(KeyStore p12ClientStore) {
        this.p12ClientStore = p12ClientStore;
    }

    public String getP12ClientSecret() {
        return p12ClientSecret;
    }

    public void setP12ClientSecret(String p12ClientSecret) {
        this.p12ClientSecret = p12ClientSecret;
    }

    public String getCaUrl() {
        return caUrl;
    }

    public void setCaUrl(String caUrl) {
        this.caUrl = caUrl;
    }

    public String getCmpAlias() {
        return cmpAlias;
    }

    public void setCmpAlias(String cmpAlias) {
        this.cmpAlias = cmpAlias;
    }

    public X500Name getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(X500Name issuerName) {
        this.issuerName = issuerName;
    }

    public AttributeTypeAndValue[] getATaVArr() {
        return aTaVArr;
    }

    public void setATaVArr(AttributeTypeAndValue[] aTaVArr) {
        this.aTaVArr = aTaVArr;
    }

    public boolean isMultipleMessages() {
        return multipleMessages;
    }

    public void setMultipleMessages(boolean multipleMessages) {
        this.multipleMessages = multipleMessages;
    }

    public boolean isVerbose() {
        return verbose;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    public void handleIssuer(JcaCertificateRequestMessageBuilder msgbuilder) {

        if( issuerName != null ) {
            msgbuilder.setIssuer(getIssuerName());

        }
    }
    public boolean isCheckTransactionIdMatch() {
        return this.checkTransactionIdMatch;
    }

    public void setCheckTransactionIdMatch(boolean checkTransactionIdMatch) {
        this.checkTransactionIdMatch = checkTransactionIdMatch;
    }
}
