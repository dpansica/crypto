package it.solutionsexmachina.crypto;

import it.solutionsexmachina.crypto.definition.GenericCryptoModule;
import it.solutionsexmachina.crypto.implementation.PGPCryptoModule;
import org.apache.commons.cli.*;

import java.io.File;
import java.util.Scanner;
import java.util.UUID;

public class CipherTool {

    public static void main(String[] args) {

        Options options = new Options();

        Option channelOption = new Option("c", "channelOption", true, "input fileOption path");
        channelOption.setRequired(false);
        options.addOption(channelOption);

        Option passwordOption = new Option("p", "passwordOption", true, "output fileOption");
        passwordOption.setRequired(false);
        options.addOption(passwordOption);

        Option textOption = new Option("t", "textOption", true, "textOption to encryptOption/decryptOption");
        textOption.setRequired(false);
        options.addOption(textOption);

        Option fileOption = new Option("f", "fileOption", true, "fileOption to encryptOption/decryptOption");
        fileOption.setRequired(false);
        options.addOption(fileOption);

        Option encryptOption = new Option("e", "encryptOption", false, "encryptOption command");
        encryptOption.setRequired(false);
        options.addOption(encryptOption);

        Option decryptOption = new Option("d", "decryptOption", false, "decryptOption command");
        decryptOption.setRequired(false);
        options.addOption(decryptOption);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("utility-name", options);

            System.exit(1);
        }

        String channel = cmd.getOptionValue("channelOption");
        String password = cmd.getOptionValue("passwordOption");
        String text = cmd.getOptionValue("textOption");
        String filename = cmd.getOptionValue("fileOption");
        boolean encrypt = cmd.hasOption("encryptOption");
        boolean decrypt = cmd.hasOption("decryptOption");

        GenericCryptoModule cryptoModule = null;

        if (channel==null){
            channel = UUID.randomUUID().toString();
            password = UUID.randomUUID().toString();
            new PGPCryptoModule(channel, password);
            System.out.println("Channel  "+channel+" generated with password: "+password);
        }

        if (encrypt){
            cryptoModule = new PGPCryptoModule(channel);

            if (text!=null){
                System.out.println(cryptoModule.encipher(text));
            }
            if (filename!=null){
                System.out.println(cryptoModule.encipher(new File(filename)));
            }
        }
        if (decrypt && password!=null){
            cryptoModule = new PGPCryptoModule(channel, password);

            if (text!=null){
                System.out.println(cryptoModule.decipher(text));
            }
            if (filename!=null){
                System.out.println(cryptoModule.decipher(new File(filename)));
            }
        }
    }

}
