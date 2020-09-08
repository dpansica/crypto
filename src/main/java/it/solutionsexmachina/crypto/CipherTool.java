package it.solutionsexmachina.crypto;

import it.solutionsexmachina.crypto.definition.GenericCryptoModule;
import it.solutionsexmachina.crypto.implementation.PGPCryptoModule;

import java.io.File;
import java.util.Scanner;
import java.util.UUID;

public class CipherTool {

    public static void main(String[] args) {

        String channelId = UUID.randomUUID().toString();

        System.out.println("Channel ID: "+channelId);

        GenericCryptoModule cryptoModule = new PGPCryptoModule(channelId, "password");

        GenericCryptoModule cryptoModuleToShare = new PGPCryptoModule(channelId);

        Scanner scanner = new Scanner(System.in);
        System.out.println("\nEnter content to encipher: ");
        String content = scanner.nextLine();

        String encipher = cryptoModuleToShare.encipher(content);

        System.out.println("Encrypted with shared key: ");
        System.out.println(encipher);

        System.out.println("Decrypted with secret key: ");
        System.out.println(cryptoModule.decipher(encipher));

        System.out.println("\nEnter file to encipher: ");
        String filename = scanner.nextLine();

        System.out.println("Encrypted with shared key: ");
        System.out.println(cryptoModuleToShare.encipher(new File(filename)));

        System.out.println("Decrypted with secret key: ");
        System.out.println(cryptoModule.decipher(new File(filename+".enc")));
    }

}
