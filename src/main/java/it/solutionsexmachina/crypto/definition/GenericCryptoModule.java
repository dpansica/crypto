package it.solutionsexmachina.crypto.definition;

import java.io.File;

public abstract class GenericCryptoModule {

    protected File initializeStore(String filename){
        String homeFolder = System.getProperty("user.home");

        File cryptoStoreFolder = new File(homeFolder + File.separator + "crypto-store");

        if (!cryptoStoreFolder.exists()) {
            cryptoStoreFolder.mkdir();
        }

        File cryptoStoreFile = new File(cryptoStoreFolder, filename);

        return cryptoStoreFile;
    }

    public abstract void initialize();

    public abstract String encipher(String content);

    public abstract String decipher(String content);

    public abstract File encipher(File file);

    public abstract File decipher(File file);
}
