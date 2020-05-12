package it.solutionsexmachina.crypto.tool;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;

import java.io.*;
import java.nio.charset.Charset;
import java.security.*;
import java.util.Date;
import java.util.Iterator;


public class PGPEncryption
{

	private static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass) throws PGPException, NoSuchProviderException
	{
		PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

		if (pgpSecKey == null)
		{
			return null;
		}

		return pgpSecKey.extractPrivateKey(pass, "BC");
	}

	public static byte[] decrypt(byte[] encrypted, InputStream keyIn, char[] password) throws IOException, PGPException, NoSuchProviderException
	{
		InputStream in = new ByteArrayInputStream(encrypted);

		in = PGPUtil.getDecoderStream(in);

		PGPObjectFactory pgpF = new PGPObjectFactory(in);
		PGPEncryptedDataList enc = null;
		Object o = pgpF.nextObject();

		//
		// the first object might be a PGP marker packet.
		//
		if (o instanceof PGPEncryptedDataList)
		{
			enc = (PGPEncryptedDataList) o;
		}
		else
		{
			enc = (PGPEncryptedDataList) pgpF.nextObject();
		}

		//
		// find the secret key
		//
		Iterator it = enc.getEncryptedDataObjects();
		PGPPrivateKey sKey = null;
		PGPPublicKeyEncryptedData pbe = null;
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));

		while (sKey == null && it.hasNext())
		{
			pbe = (PGPPublicKeyEncryptedData) it.next();

			sKey = findSecretKey(pgpSec, pbe.getKeyID(), password);
		}

		if (sKey == null)
		{
			throw new IllegalArgumentException("secret key for message not found.");
		}

		InputStream clear = pbe.getDataStream(sKey, "BC");

		PGPObjectFactory pgpFact = new PGPObjectFactory(clear);

		Object next = pgpFact.nextObject();

		PGPLiteralData ld;
		if (next instanceof PGPLiteralData)
		{
			ld = (PGPLiteralData) next;
		}
		else
		{
			PGPCompressedData cData = (PGPCompressedData) next;
			pgpFact = new PGPObjectFactory(cData.getDataStream());
			ld = (PGPLiteralData) pgpFact.nextObject();
		}

		InputStream unc = ld.getInputStream();

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int ch;

		while ((ch = unc.read()) >= 0)
		{
			out.write(ch);

		}

		byte[] returnBytes = out.toByteArray();
		out.close();
		return returnBytes;
	}

	public static String decrypt(String toBeDecrypted, PGPPrivateKey sKey) throws IOException, PGPException, NoSuchProviderException
	{
		String decryptedString = null;

		if (toBeDecrypted!=null) {

			byte[] decrypted = toBeDecrypted.getBytes();

			BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
			Security.addProvider(bouncyCastleProvider);

			InputStream in = new ByteArrayInputStream(decrypted);

			in = PGPUtil.getDecoderStream(in);

			PGPObjectFactory pgpF = new PGPObjectFactory(in);
			PGPEncryptedDataList enc = null;
			Object o = pgpF.nextObject();

			if (o instanceof PGPEncryptedDataList) {
				enc = (PGPEncryptedDataList) o;
			} else {
				enc = (PGPEncryptedDataList) pgpF.nextObject();
			}

			byte[] returnBytes = new byte[0];
			if (!enc.isEmpty()) {
				PGPPublicKeyEncryptedData pbe = (PGPPublicKeyEncryptedData) enc.get(0);
				InputStream clear = pbe.getDataStream(sKey, "BC");

				PGPObjectFactory pgpFact = new PGPObjectFactory(clear);

				Object next = pgpFact.nextObject();

				PGPLiteralData ld;
				if (next instanceof PGPLiteralData) {
					ld = (PGPLiteralData) next;
				} else {
					PGPCompressedData cData = (PGPCompressedData) next;
					pgpFact = new PGPObjectFactory(cData.getDataStream());
					ld = (PGPLiteralData) pgpFact.nextObject();
				}

				InputStream unc = ld.getInputStream();

				ByteArrayOutputStream out = new ByteArrayOutputStream();
				int ch;

				while ((ch = unc.read()) >= 0) {
					out.write(ch);

				}

				decryptedString = out.toString();
				out.close();
			}
		}

		return decryptedString;
	}

	public static String encrypt(String toBeEncrypted, PGPPublicKey encKey, String fileName, boolean withIntegrityCheck, boolean armor) throws IOException, PGPException, NoSuchProviderException
	{
		byte[] clearData = toBeEncrypted.getBytes();

		if (fileName == null)
		{
			fileName = PGPLiteralData.CONSOLE;
		}

		ByteArrayOutputStream encOut = new ByteArrayOutputStream();

		OutputStream out = encOut;
		if (armor)
		{
			out = new ArmoredOutputStream(out);
		}

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
		OutputStream cos = comData.open(bOut);

		PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();


		OutputStream pOut = lData.open(cos,
				PGPLiteralData.BINARY, fileName,
				clearData.length,
				new Date()
		);
		pOut.write(clearData);

		lData.close();
		comData.close();

		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, withIntegrityCheck, new SecureRandom(), "BC");

		cPk.addMethod(encKey);

		byte[] bytes = bOut.toByteArray();

		OutputStream cOut = cPk.open(out, bytes.length);

		cOut.write(bytes);
		cOut.close();

		out.close();

		return encOut.toString();
	}

	public static PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException
	{
		in = PGPUtil.getDecoderStream(in);

		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in);

		Iterator rIt = pgpPub.getKeyRings();

		while (rIt.hasNext())
		{
			PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
			Iterator kIt = kRing.getPublicKeys();

			while (kIt.hasNext())
			{
				PGPPublicKey k = (PGPPublicKey) kIt.next();

				if (k.isEncryptionKey())
				{
					return k;
				}
			}
		}

		throw new IllegalArgumentException("Can't find encryption key in key ring.");
	}

	public static byte[] getBytesFromFile(File file) throws IOException
	{
		InputStream is = new FileInputStream(file);

		long length = file.length();

		if (length > Integer.MAX_VALUE)
		{

		}


		byte[] bytes = new byte[(int) length];


		int offset = 0;
		int numRead = 0;
		while (offset < bytes.length && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0)
		{
			offset += numRead;
		}

		if (offset < bytes.length)
		{
			throw new IOException("Could not completely read file " + file.getName());
		}

		is.close();
		return bytes;
	}

	public static PGPSecretKeyRing createKey(String password)
	{
		KeyPair keyPair = null;
		PGPKeyPair secretKey = null;
		PGPSecretKeyRing skr = null;

		try
		{

			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");

			keyPairGen.initialize(512);

			keyPair = keyPairGen.generateKeyPair();

			PGPSignatureSubpacketGenerator hashedGen = new PGPSignatureSubpacketGenerator();

			hashedGen.setKeyFlags(true, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA | KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

			hashedGen.setPreferredCompressionAlgorithms(false, new int[] { CompressionAlgorithmTags.ZIP });

			hashedGen.setPreferredHashAlgorithms(false, new int[] { HashAlgorithmTags.SHA1 });

			hashedGen.setPreferredSymmetricAlgorithms(false, new int[] { SymmetricKeyAlgorithmTags.AES_256 });

			secretKey = new PGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPair, new Date());

			PGPKeyPair secretKey2 = new PGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPair, new Date());

			PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, secretKey, "<secure@welld.ch>", PGPEncryptedData.AES_256, password.toCharArray(), true, hashedGen.generate(), null, new SecureRandom(), "BC");

			keyRingGen.addSubKey(secretKey2);

			skr = keyRingGen.generateSecretKeyRing();

		}
		catch (Exception e)
		{

			e.printStackTrace();
		}

		return skr;
	}

	public static void main(String[] args) throws Exception
	{
		BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
		Security.addProvider(bouncyCastleProvider);
		
		PGPSecretKeyRing key = generateKeyPair("password");

        String armoredPublicKey = getArmoredPublicKey(key.getPublicKey());
        System.out.println(armoredPublicKey);
        PGPPublicKey pgpPublicKey = importPublicKey(armoredPublicKey);

        String armoredPrivateKey = getArmoredSecretKey(key.getSecretKey());
        System.out.println(armoredPrivateKey);
        PGPSecretKey pgpSecretKey = importSecretKey(armoredPrivateKey);

        String toBeEncrypted = "Hello Crypto World";

		System.out.println("String to be encrypted: "+toBeEncrypted);

		String encrypted = encrypt(toBeEncrypted, pgpPublicKey, null, true, true);

		System.out.println("PGP Encrypted: "+encrypted);

		String decrypted = decrypt(encrypted, pgpSecretKey.extractPrivateKey("password".toCharArray(), bouncyCastleProvider));

		System.out.println("PGP Decrypted: "+decrypted);

	}
	
	public static PGPSecretKeyRing generateKeyPair(String password)
	{
		BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
		Security.addProvider(bouncyCastleProvider);

		PGPSecretKeyRing key = createKey(password);
		
		return key;
	}

	public static String getArmoredPublicKey(PGPPublicKey key) throws IOException
	{
		ByteArrayOutputStream encOut = new ByteArrayOutputStream();
		ArmoredOutputStream armorOut = new ArmoredOutputStream(encOut);

		armorOut.write(key.getEncoded());
		armorOut.flush();
		armorOut.close();
		return new String(encOut.toByteArray());
	}

	public static PGPPublicKey importPublicKey(String keyText){
        try {
            InputStream inputStream = new ByteArrayInputStream(keyText.getBytes(Charset.forName("UTF-8")));
            InputStream decoderStream = PGPUtil.getDecoderStream(inputStream);
            PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(decoderStream);

            PGPPublicKey key = null;
            Iterator rIt = pgpPub.getKeyRings();
            while (key == null && rIt.hasNext()) {
                PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
                Iterator kIt = kRing.getPublicKeys();
                while (key == null && kIt.hasNext()) {
                    PGPPublicKey k = (PGPPublicKey) kIt.next();
                    if (k.isEncryptionKey()) {
                        key = k;
                    }
                }
            }
            return key;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }

        return null;
    }
	
	public static String getArmoredSecretKey(PGPSecretKey key) throws IOException
	{
		ByteArrayOutputStream encOut = new ByteArrayOutputStream();
		ArmoredOutputStream armorOut = new ArmoredOutputStream(encOut);

		armorOut.write(key.getEncoded());
		armorOut.flush();
		armorOut.close();
		return new String(encOut.toByteArray());
	}

    public static PGPSecretKey importSecretKey(String keyText){
        try {
            InputStream inputStream = new ByteArrayInputStream(keyText.getBytes(Charset.forName("UTF-8")));
            InputStream decoderStream = PGPUtil.getDecoderStream(inputStream);
			InputStream pgpIn = PGPUtil.getDecoderStream(decoderStream);

			PGPObjectFactory pgpFact = new PGPObjectFactory(pgpIn);
			PGPSecretKeyRing pgpSecRing = (PGPSecretKeyRing)pgpFact.nextObject();
			PGPSecretKey secretKey = pgpSecRing.getSecretKey();

			return secretKey;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }
}
