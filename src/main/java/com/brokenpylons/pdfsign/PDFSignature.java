package com.brokenpylons.pdfsign;

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
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.util.Matrix;

import java.awt.*;
import java.awt.geom.AffineTransform;
import java.io.*;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;

class PDFSignature {
    // create a template PDF document with empty signature and return it as a stream.
    private static InputStream createVisualSignatureTemplate(PDDocument srcDoc, int pageNum, PDRectangle rect, PDSignature signature) throws IOException {
        try (PDDocument doc = new PDDocument()) {
            PDPage page = new PDPage(srcDoc.getPage(pageNum).getMediaBox());
            doc.addPage(page);

            PDAcroForm acroForm = new PDAcroForm(doc);
            doc.getDocumentCatalog().setAcroForm(acroForm);

            PDSignatureField signatureField = new PDSignatureField(acroForm);
            acroForm.setSignaturesExist(true);
            acroForm.setAppendOnly(true);
            acroForm.getCOSObject().setDirect(true);

            List<PDField> acroFormFields = acroForm.getFields();
            acroFormFields.add(signatureField);

            PDAnnotationWidget widget = signatureField.getWidgets().get(0);
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
            switch (srcDoc.getPage(pageNum).getRotation()) {
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

            try (PDPageContentStream cs = new PDPageContentStream(doc, appearanceStream)) {
                // for 90Ã‚Â° and 270Ã‚Â° scale ratio of width / height
                // not really sure about this
                // why does scale have no effect when done in the form matrix???
                if (initialScale != null) {
                    cs.transform(initialScale);
                }

                // show background (just for debugging, to see the rect size + position)
                cs.setNonStrokingColor(Color.white);
                cs.addRect(-5000, -5000, 10000, 10000);
                cs.fill();

                // show background image
                // save and restore graphics if the image is too large and needs to be scaled
                cs.saveGraphicsState();
                cs.transform(Matrix.getScaleInstance(0.06f, 0.06f));
                PDImageXObject img = PDImageXObject.createFromFileByExtension(new File("image.jpg"), doc);
                cs.drawImage(img, 0, 0);
                cs.restoreGraphicsState();

                // show text
                float fontSize = 10;
                float leading = fontSize * 1.5f;
                cs.beginText();
                cs.setFont(font, fontSize);
                cs.setNonStrokingColor(Color.black);
                cs.newLineAtOffset(fontSize * 3 , height - leading);
                cs.setLeading(leading);

                String name = signature.getName();
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

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            doc.save(baos);
            return new ByteArrayInputStream(baos.toByteArray());
        }
    }

    public static void sign(InputStream input, OutputStream output, Config config, SignatureInterface signatureInterface) throws IOException {
        PDDocument document = PDDocument.load(input);
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);

        signature.setName(config.name);
        signature.setReason(config.reason);
        signature.setLocation(config.location);

        var calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("Europe/Ljubljana"));
        signature.setSignDate(calendar);

        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setPage(0);

        signatureOptions.setVisualSignature(createVisualSignatureTemplate(document, 0, new PDRectangle(config.x, config.y, 200, 50), signature));
        //signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);

        document.addSignature(signature, signatureInterface, signatureOptions);
        document.saveIncremental(output);
    }
}
