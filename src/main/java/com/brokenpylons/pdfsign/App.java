package com.brokenpylons.pdfsign;

import com.brokenpylons.pdfsign.security.FileKeyStoreSource;
import com.brokenpylons.pdfsign.security.Signer;
import com.brokenpylons.pdfsign.security.SmartCardKeyStoreSource;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ArgGroup;

import java.io.*;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.concurrent.Callable;

@Command(name = "pdfsign", description = "Crappy pdf signer")
public class App implements Callable<Integer> {

    @Parameters(index = "0", description = "Input file")
    private File inputFile;

    @Parameters(index = "1", description = "Output file")
    private File outputFile;

    @ArgGroup(exclusive = true, multiplicity = "1")
    Source source;

    @Option(names={"-n", "--name"})
    String name;

    @Option(names={"-r", "--reason"})
    String reason;

    @Option(names={"-l", "--location"})
    String location;

    @Option(names={"-x"})
    int x = 100;

    @Option(names={"-y"})
    int y = 100;

    static class Source {
        @Option(names = "-c", required = true, description = "Use a smart card")
        private Path config;

        @Option(names = "-f", required = true, description = "Load the certificate from a file")
        private File keystoreFile;
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new App()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {

            char[] password = System.console().readPassword("PIN:");
            KeyStore keyStore = null;
            if (source.keystoreFile != null) {
                keyStore = new FileKeyStoreSource(source.keystoreFile, password).getKeyStore();
            } else if (source.config != null) {
                keyStore = new SmartCardKeyStoreSource(source.config.toString(), password).getKeyStore();
            } else {
                throw new RuntimeException();
            }

            var signatureInterface = new Signature(new Signer(keyStore, password));
            var config = new Config(name, reason, location, x, y);
            PDFSignature.sign(inputStream, outputStream, config, signatureInterface);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return 0;
    }
}
