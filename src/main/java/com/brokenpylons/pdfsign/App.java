package com.brokenpylons.pdfsign;
import java.awt.*;
import java.awt.geom.AffineTransform;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.List;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.util.Matrix;
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

    @Override
    public byte[] sign(final InputStream input) throws IOException {
        try {
            var generator = new CMSSignedDataGenerator();
            var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(key);
            var digestCalculator = new JcaDigestCalculatorProviderBuilder().build();
            generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digestCalculator).build(signer, certificate));
            generator.addCertificates(new JcaCertStore(Arrays.asList(this.certificateChain)));

            var stream = new CMSProcessableByteArray(input.readAllBytes());
            var data = generator.generate(stream);
            return data.getEncoded();
        } catch (GeneralSecurityException | OperatorCreationException | CMSException e) {
            throw new RuntimeException(e);
        }
    }
}

public class App 
{
    // create a template PDF document with empty signature and return it as a stream.
    private static InputStream createVisualSignatureTemplate(PDDocument srcDoc, int pageNum,
                                                             PDRectangle rect, PDSignature signature) throws IOException
    {
        try (PDDocument doc = new PDDocument())
        {
            PDPage page = new PDPage(srcDoc.getPage(pageNum).getMediaBox());
            doc.addPage(page);
            PDAcroForm acroForm = new PDAcroForm(doc);
            doc.getDocumentCatalog().setAcroForm(acroForm);
            PDSignatureField signatureField = new PDSignatureField(acroForm);
            PDAnnotationWidget widget = signatureField.getWidgets().get(0);
            List<PDField> acroFormFields = acroForm.getFields();
            acroForm.setSignaturesExist(true);
            acroForm.setAppendOnly(true);
            acroForm.getCOSObject().setDirect(true);
            acroFormFields.add(signatureField);

            widget.setRectangle(rect);

            // from PDVisualSigBuilder.createHolderForm()
            PDStream stream = new PDStream(doc);
            PDFormXObject form = new PDFormXObject(stream);
            PDResources res = new PDResources();
            form.setResources(res);
            form.setFormType(1);
            PDRectangle bbox = new PDRectangle(rect.getWidth(), rect.getHeight());
            float height = bbox.getHeight();
            Matrix initialScale = null;
            switch (srcDoc.getPage(pageNum).getRotation())
            {
                case 90:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(1));
                    initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(), bbox.getHeight() / bbox.getWidth());
                    height = bbox.getWidth();
                    break;
                case 180:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(2));
                    break;
                case 270:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(3));
                    initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(), bbox.getHeight() / bbox.getWidth());
                    height = bbox.getWidth();
                    break;
                case 0:
                default:
                    break;
            }
            form.setBBox(bbox);
            PDFont font = PDType1Font.HELVETICA_BOLD;

            // from PDVisualSigBuilder.createAppearanceDictionary()
            PDAppearanceDictionary appearance = new PDAppearanceDictionary();
            appearance.getCOSObject().setDirect(true);
            PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
            appearance.setNormalAppearance(appearanceStream);
            widget.setAppearance(appearance);

            try (PDPageContentStream cs = new PDPageContentStream(doc, appearanceStream))
            {
                // for 90Ã‚Â° and 270Ã‚Â° scale ratio of width / height
                // not really sure about this
                // why does scale have no effect when done in the form matrix???
                if (initialScale != null)
                {
                    cs.transform(initialScale);
                }

                // show background (just for debugging, to see the rect size + position)
                cs.setNonStrokingColor(Color.yellow);
                cs.addRect(-5000, -5000, 10000, 10000);
                cs.fill();

                // show background image
                // save and restore graphics if the image is too large and needs to be scaled
                cs.saveGraphicsState();
                cs.transform(Matrix.getScaleInstance(0.25f, 0.25f));
                //PDImageXObject img = PDImageXObject.createFromFileByExtension(new File("image.png"), doc);
                //cs.drawImage(img, 0, 0);
                cs.restoreGraphicsState();

                // show text
                float fontSize = 10;
                float leading = fontSize * 1.5f;
                cs.beginText();
                cs.setFont(font, fontSize);
                cs.setNonStrokingColor(Color.black);
                cs.newLineAtOffset(fontSize, height - leading);
                cs.setLeading(leading);

                /*X509Certificate cert = (X509Certificate) getCertificateChain()[0];

                // https://stackoverflow.com/questions/2914521/
                X500Name x500Name = new X500Name(cert.getSubjectX500Principal().getName());
                RDN cn = x500Name.getRDNs(BCStyle.CN)[0];*/
                String name = ""; // IETFUtils.valueToString(cn.getFirst().getValue());

                // See https://stackoverflow.com/questions/12575990
                // for better date formatting
                String date = signature.getSignDate().getTime().toString();
                String reason = signature.getReason();

                cs.showText("Signer: " + name);
                cs.newLine();
                cs.showText(date);
                cs.newLine();
                //cs.showText("Reason: " + reason);

                cs.endText();
            }

            // no need to set annotations and /P entry

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            doc.save(baos);
            return new ByteArrayInputStream(baos.toByteArray());
        }
    }

    public static void sign(InputStream input, OutputStream output, SignatureInterface signatureInterface) throws IOException {
        PDDocument document = PDDocument.load(input);
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);

        signature.setName("");
        signature.setLocation("");
        //signature.setReason("Reason");

        var calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("Europe/Ljubljana"));
        signature.setSignDate(calendar);


        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setPage(0);
        signatureOptions.setVisualSignature(createVisualSignatureTemplate(document, 0, new PDRectangle(100, 150, 170, 50), signature));
        //signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);

        document.addSignature(signature, signatureInterface, signatureOptions);
        document.saveIncremental(output);
    }

    public static void main(String[] args) {

        File inputFile = new File("");
        File outputFile = new File("");
        File keystoreFile = new File("");
        String password = "";
        String alias = "";

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
