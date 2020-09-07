package com.brokenpylons.pdfsign.security;

import javax.security.auth.Subject;
import javax.security.cert.X509Certificate;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class SmartCardKeyStoreSource implements KeyStoreSource {
    private KeyStore keyStore;

    public SmartCardKeyStoreSource(String config, char[] password) {
        var provider = Security.getProvider("SunPKCS11");
        AuthProvider authProvider = (AuthProvider)provider.configure(config);
        Security.addProvider(authProvider);

        try {
            keyStore = KeyStore.getInstance("PKCS11", authProvider);
            keyStore.load(null, password);
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public KeyStore getKeyStore() {
        return keyStore;
    }
}
