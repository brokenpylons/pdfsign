package com.brokenpylons.pdfsign;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;


class Sign implements SignatureInterface {
    PrivateKey key;

    public Sign(File file, String password, String alias) throws IOException {
        try {
            final KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(new FileInputStream(file), password.toCharArray());
            this.key = (PrivateKey)store.getKey(alias, password.toCharArray());
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] sign(final InputStream input) throws IOException {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(key);
            signature.update(input.readAllBytes());
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}

public class App 
{
    public static void createVisualSignature() {

    }
    public static void sign(InputStream input, OutputStream output, SignatureInterface signatureInterface) throws IOException {
        PDDocument document = PDDocument.load(input);
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);

        signature.setName("Name");
        signature.setLocation("Location");
        signature.setReason("Reason");
        signature.setSignDate(Calendar.getInstance());

        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setPage(0);
        document.addSignature(signature, signatureInterface); //, signatureOptions);
        document.saveIncremental(output);
    }

    public static void main(String[] args) {

        File inputFile = new File("test.pdf");
        File outputFile = new File("test_sig.pdf");

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {

            SignatureInterface signatureInterface = new Sign(keystoreFile, password, alias);
            sign(inputStream, outputStream, signatureInterface);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        System.out.println("Hello");
    }
}
