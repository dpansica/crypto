package it.solutionsexmachina.crypto;

import it.solutionsexmachina.crypto.definition.GenericCryptoModule;
import it.solutionsexmachina.crypto.implementation.PGPCryptoModule;

import java.io.File;
import java.util.Scanner;

public class CipherTool {

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);
        System.out.println("\nEnter content to encipher: ");
        String content = scanner.nextLine();

//        GenericCryptoModule cryptoModule = new PGPCryptoModule();
//        cryptoModule.initialize();

        GenericCryptoModule cryptoModule = new PGPCryptoModule("password");

        String encipher = cryptoModule.encipher(content);

        System.out.println(encipher);

        System.out.println(cryptoModule.decipher(encipher));

        System.out.println(cryptoModule.encipher(new File("/home/diego/Desktop/Enel/Fattura_0000002937551477.pdf")));

        System.out.println(cryptoModule.decipher(new File("/home/diego/Desktop/Enel/Fattura_0000002937551477.pdf.enc")));
    }

}
