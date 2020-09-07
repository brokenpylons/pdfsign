package com.brokenpylons.pdfsign.security;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import javax.security.auth.Subject;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.stream.Collectors;
import javax.security.auth.callback.*;
import javax.security.auth.login.LoginException;

public class Signer {
    PrivateKey key;
    X509Certificate certificate;
    Certificate[] certificateChain;
    KeyStore keyStore;

    public Signer(KeyStore keyStore, char[] password) {
        try {
            var alias = Collections.list(keyStore.aliases())
                    .stream()
                    .filter(Objects::nonNull)
                    .findFirst()
                    .orElseThrow();

            this.keyStore = keyStore;
            key = (PrivateKey) keyStore.getKey(alias, password);
            certificate = (X509Certificate) keyStore.getCertificate(alias);
            certificateChain = keyStore.getCertificateChain(alias);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] sign(byte[] input) {
        try {
            var generator = new CMSSignedDataGenerator();
            var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(key);
            var digestCalculator = new JcaDigestCalculatorProviderBuilder().build();
            generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digestCalculator).build(signer, certificate));
            generator.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));

            var buffer = new CMSProcessableByteArray(input);
            var data = generator.generate(buffer, false);
            return data.getEncoded();
        } catch (GeneralSecurityException | OperatorCreationException | CMSException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
