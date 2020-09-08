package it.solutionsexmachina.crypto.implementation;

import it.solutionsexmachina.crypto.definition.GenericCryptoModule;
import it.solutionsexmachina.crypto.tool.PGPEncryption;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;
import java.util.Scanner;
import java.util.UUID;

public class PGPCryptoModule extends GenericCryptoModule {

    private PGPSecretKey secretKey;

    private String password;

    public PGPCryptoModule(String channelId, String password){
        try {
            initSecretKey(channelId, password);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public PGPCryptoModule(String channelId){
        try {
            initSecretKey(channelId, null);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public PGPCryptoModule() {

    }

    @Override
    public void initialize() {
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.println("\nEnter password to cipher (Be sure to remember your password): ");

            initSecretKey(UUID.randomUUID().toString(), scanner.nextLine());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void initSecretKey(String channelId, String password) throws IOException {
        this.password = password;

        File privateKeyFile = initializeStore(channelId, "pgp-secret.txt");

        if (!privateKeyFile.exists()) {

            PGPSecretKeyRing key = PGPEncryption.generateKeyPair(password);

            String armoredSecretKey = PGPEncryption.getArmoredSecretKey(key.getSecretKey());

            FileUtils.writeStringToFile(privateKeyFile, armoredSecretKey, Charset.forName("UTF-8"));

            this.secretKey = key.getSecretKey();

        } else {
            this.secretKey = PGPEncryption.importSecretKey(FileUtils.readFileToString(privateKeyFile, Charset.forName("UTF-8")));
        }
    }

    @Override
    public String encipher(String content) {
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);
        PGPEncryption pgpEncryption = new PGPEncryption();

        try {
            return pgpEncryption.encrypt(content, this.secretKey.getPublicKey(), null, true, true);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        return content;
    }

    @Override
    public String decipher(String content) {
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);

        PGPEncryption pgpEncryption = new PGPEncryption();

        try {
            return pgpEncryption.decrypt(content, this.secretKey.extractPrivateKey(this.password.toCharArray(), bouncyCastleProvider));
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        return content;
    }

    @Override
    public File encipher(File file) {
        try {
            byte[] encoded = Base64.getEncoder().encode(FileUtils.readFileToByteArray(file));
            String base64 = new String(encoded, StandardCharsets.UTF_8);

            String encipherContent = encipher(base64);

            String folder = file.getParentFile().getAbsolutePath();
            String encFilename = file.getName()+".enc";

            File encFile = new File(folder, encFilename);
            FileUtils.writeStringToFile(encFile, encipherContent, StandardCharsets.UTF_8);

            return encFile;

        } catch (IOException e) {
            e.printStackTrace();
        }

        return file;
    }

    @Override
    public File decipher(File file) {

        try {
            String content = FileUtils.readFileToString(file, StandardCharsets.UTF_8);

            String base64 = decipher(content);

            String folder = file.getParentFile().getAbsolutePath();
            String decFilename = file.getName().substring(0, file.getName().indexOf(".enc"));

            byte[] data = Base64.getDecoder().decode(base64);
            File decFile = new File(folder, decFilename);
            try (OutputStream stream = new FileOutputStream(decFile) ){
                stream.write(data);
            }

            return decFile;

        } catch (IOException e) {
            e.printStackTrace();
        }

        return file;
    }
}
