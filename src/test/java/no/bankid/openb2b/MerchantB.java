package no.bankid.openb2b;

import java.net.URL;

public class MerchantB extends Merchant {

    @Override
    protected String getCommonName() {
        return "Merchant B";
    }

    @Override
    protected String getOrganizationNumber() {
        return "999999999";
    }

    @Override
    protected String getKeyAlias() {
        return "signkey";
    }

    @Override
    protected char[] getKeyStorePassword() {
        return "qwer1234".toCharArray();
    }

    @Override
    protected URL getKeyStoreUrl() {
        return MerchantB.class.getResource("/Merchant_B.sign.p12");
    }

    @Override
    protected char[] getKeyPassword() {
        return "qwer1234".toCharArray();
    }
}
