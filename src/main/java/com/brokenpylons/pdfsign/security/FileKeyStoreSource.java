package com.brokenpylons.pdfsign.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class FileKeyStoreSource implements KeyStoreSource {
    final KeyStore keyStore;

    public FileKeyStoreSource(File file, char[] password) {
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream(file), password);
        } catch (KeyStoreException | NoSuchAlgorithmException| CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public KeyStore getKeyStore() {
        return keyStore;
    }
}
