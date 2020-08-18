package com.brokenpylons.pdfsign;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;


class Sign implements SignatureInterface {
    PrivateKey key;
    X509Certificate certificate;
    Certificate[] certificateChain;

    public Sign(File file, String password, String alias) throws IOException {
        try {
            final var store = KeyStore.getInstance("PKCS12");
            store.load(new FileInputStream(file), password.toCharArray());
            this.key = (PrivateKey)store.getKey(alias, password.toCharArray());
            this.certificate = (X509Certificate)store.getCertificate(alias);
            this.certificateChain = store.getCertificateChain(alias);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public class CMSProcessableInputStream implements CMSTypedData {
        private final InputStream inputStream;
        private final ASN1ObjectIdentifier contentType;

        CMSProcessableInputStream(InputStream is) {
            this(new ASN1ObjectIdentifier(CMSObjectIdentifiers.data.getId()), is);
        }

        private CMSProcessableInputStream(ASN1ObjectIdentifier type, InputStream is) {
            contentType = type;
            inputStream = is;
        }

        @Override
        public Object getContent() {
            return inputStream;
        }

        @Override
        public void write(OutputStream out) throws IOException {
            // read the content only one time
            IOUtils.copy(inputStream, out);
            inputStream.close();
        }

        @Override
        public ASN1ObjectIdentifier getContentType() {
            return contentType;
        }
    }

    @Override
    public byte[] sign(final InputStream input) throws IOException {
        try {
            /*var generator = new CMSSignedDataGenerator();
            var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(key);
            var calculator = new JcaDigestCalculatorProviderBuilder().build();
            generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(calculator).build(signer, certificate));
            generator.addCertificates(new JcaCertStore(Arrays.asList(this.certificateChain)));

            var stream = new CMSProcessableByteArray(input.readAllBytes());
            var data = generator.generate(stream);
            return data.getEncoded();*/

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            X509Certificate cert = (X509Certificate) this.certificateChain[0];
            ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(this.key);
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha1Signer, cert));
            gen.addCertificates(new JcaCertStore(Arrays.asList(this.certificateChain)));
            CMSProcessableInputStream msg = new CMSProcessableInputStream(input);
            CMSSignedData signedData = gen.generate(msg, false);
            return signedData.getEncoded();

        } catch (GeneralSecurityException | OperatorCreationException | CMSException e) {
            throw new RuntimeException(e);
        }
    }
}

public class App 
{
    public static void createVisualSignature() {

    }

    public static int getMDPPermission(PDDocument doc)
    {
        COSBase base = doc.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.PERMS);
        if (base instanceof COSDictionary)
        {
            COSDictionary permsDict = (COSDictionary) base;
            base = permsDict.getDictionaryObject(COSName.DOCMDP);
            if (base instanceof COSDictionary)
            {
                COSDictionary signatureDict = (COSDictionary) base;
                base = signatureDict.getDictionaryObject("Reference");
                if (base instanceof COSArray)
                {
                    COSArray refArray = (COSArray) base;
                    for (int i = 0; i < refArray.size(); ++i)
                    {
                        base = refArray.getObject(i);
                        if (base instanceof COSDictionary)
                        {
                            COSDictionary sigRefDict = (COSDictionary) base;
                            if (COSName.DOCMDP.equals(sigRefDict.getDictionaryObject("TransformMethod")))
                            {
                                base = sigRefDict.getDictionaryObject("TransformParams");
                                if (base instanceof COSDictionary)
                                {
                                    COSDictionary transformDict = (COSDictionary) base;
                                    int accessPermissions = transformDict.getInt(COSName.P, 2);
                                    if (accessPermissions < 1 || accessPermissions > 3)
                                    {
                                        accessPermissions = 2;
                                    }
                                    return accessPermissions;
                                }
                            }
                        }
                    }
                }
            }
        }
        return 0;
    }

    public static void setMDPPermission(PDDocument doc, PDSignature signature, int accessPermissions)
    {
        COSDictionary sigDict = signature.getCOSObject();

        // DocMDP specific stuff
        COSDictionary transformParameters = new COSDictionary();
        transformParameters.setItem(COSName.TYPE, COSName.getPDFName("TransformParams"));
        transformParameters.setInt(COSName.P, accessPermissions);
        transformParameters.setName(COSName.V, "1.2");
        transformParameters.setNeedToBeUpdated(true);

        COSDictionary referenceDict = new COSDictionary();
        referenceDict.setItem(COSName.TYPE, COSName.getPDFName("SigRef"));
        referenceDict.setItem("TransformMethod", COSName.DOCMDP);
        referenceDict.setItem("DigestMethod", COSName.getPDFName("SHA1"));
        referenceDict.setItem("TransformParams", transformParameters);
        referenceDict.setNeedToBeUpdated(true);

        COSArray referenceArray = new COSArray();
        referenceArray.add(referenceDict);
        sigDict.setItem("Reference", referenceArray);
        referenceArray.setNeedToBeUpdated(true);

        // Catalog
        COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
        COSDictionary permsDict = new COSDictionary();
        catalogDict.setItem(COSName.PERMS, permsDict);
        permsDict.setItem(COSName.DOCMDP, signature);
        catalogDict.setNeedToBeUpdated(true);
        permsDict.setNeedToBeUpdated(true);
    }

    public static void sign(InputStream input, OutputStream output, SignatureInterface signatureInterface) throws IOException {
        PDDocument document = PDDocument.load(input);
        int accessPermissions = getMDPPermission(document);
        if (accessPermissions == 1)
        {
            throw new IllegalStateException("No changes to the document are permitted due to DocMDP transform parameters dictionary");
        }
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);

        signature.setName("Name");
        signature.setLocation("Location");
        signature.setReason("Reason");
        signature.setSignDate(Calendar.getInstance());

        if (accessPermissions == 0)
        {
            setMDPPermission(document, signature, 2);
        }

        /*SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setPage(0);*/
        SignatureOptions signatureOptions = new SignatureOptions();
         	            // Size can vary, but should be enough for purpose.
         	            signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);
        document.addSignature(signature, signatureInterface, signatureOptions);
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
