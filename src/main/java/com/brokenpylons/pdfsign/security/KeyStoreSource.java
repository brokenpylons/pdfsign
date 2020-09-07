package com.brokenpylons.pdfsign.security;

import java.security.KeyStore;
import java.security.cert.X509Certificate;

public interface KeyStoreSource {
    KeyStore getKeyStore();
}
