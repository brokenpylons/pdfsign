package com.brokenpylons.pdfsign;

import com.brokenpylons.pdfsign.security.Signer;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

import java.io.IOException;
import java.io.InputStream;

class Signature implements SignatureInterface {
    final Signer signer;

    Signature(Signer signer) {
        this.signer = signer;
    }

    @Override
    public byte[] sign(InputStream inputStream) throws IOException {
        return signer.sign(inputStream.readAllBytes());
    }
}
