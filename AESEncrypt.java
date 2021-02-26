
import java.io.FileReader;
import java.io.FileWriter;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.util.Arrays;

import org.graalvm.compiler.virtual.phases.ea.PartialEscapeBlockState.Final;

import java.nio.charset.StandardCharsets;


public class AESEncrypt {
	
	static Cipher cipher;
	static String plainText;


	private final static int SUGAR = 0x9E3779B9;
	private final static int CUPS  = 32;
	private final static int UNSUGAR = 0xC6EF3720;

	private final static int[] S = new int[4];

	public static void aesIni(final String pText) throws Exception {
		plainText = pText;
		final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);

		/** 4 key generation for four roun of aes */
		final SecretKey secretKey1 = keyGenerator.generateKey();
		final SecretKey secretKey2 = keyGenerator.generateKey();
		final SecretKey secretKey3 = keyGenerator.generateKey();
		final SecretKey secretKey4 = keyGenerator.generateKey();
		cipher = Cipher.getInstance("AES");
		/** 4 round of aes encryption */
		final String encryptedText1 = encrypt(pText, secretKey1);
		final String encryptedText2 = encrypt(encryptedText1, secretKey2);
		final String encryptedText3 = encrypt(encryptedText2, secretKey3);
		final String encryptedText = encrypt(encryptedText3, secretKey4);

		final byte[] crypt = AESEncrypt.Tencrypt(encryptedText.getBytes());
		final String encf = new String(crypt,java.nio.charset.StandardCharsets.ISO_8859_1);
		/** writing encrypted data to text file */
		final FileWriter fw = new FileWriter("/home/unish/Desktop/encrypted file.txt");
		fw.write(encf);
		fw.close();

		System.out.println();
		System.out.println("Encrypted Text After Encryption: \n" + encf);

		/** reading encrypted file , Decryption Starts */
		String enText = "";
		final FileReader fr = new FileReader("/home/unish/Desktop/encrypted file.txt");
		int i;
		while ((i = fr.read()) != -1) {
			final char c = (char) i;
			enText = enText + Character.toString(c);
		}
		fr.close();

		// System.out.println(enText);
		final byte[] result = AESEncrypt.Tdecrypt(enText.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
		final String decf = new String(result);

		/** 4 round of aes decryption */
		final String decryptedText1 = decrypt(decf, secretKey4);
		final String decryptedText2 = decrypt(decryptedText1, secretKey3);
		final String decryptedText3 = decrypt(decryptedText2, secretKey2);
		final String decryptedText = decrypt(decryptedText3, secretKey1);

		/** writing decrypted data to file */
		final FileWriter fw1 = new FileWriter("/home/unish/Desktop/decrypted file.txt");
		fw1.write(decryptedText);
		fw1.close();
		System.out.println();
		System.out.println("Decrypted Text After Decryption: \n" + decryptedText);
	}

	public static String encrypt(final String plainText, final SecretKey secretKey) throws Exception {
		final byte[] plainTextByte = plainText.getBytes();
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		final byte[] encryptedByte = cipher.doFinal(plainTextByte);
		final Base64.Encoder encoder = Base64.getEncoder();
		final String encryptedText = encoder.encodeToString(encryptedByte);
		return encryptedText;
	}

	public static String decrypt(final String encryptedText, final SecretKey secretKey) throws Exception {
		final Base64.Decoder decoder = Base64.getDecoder();
		final byte[] encryptedTextByte = decoder.decode(encryptedText);
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		final byte[] decryptedByte = cipher.doFinal(encryptedTextByte);
		final String decryptedText = new String(decryptedByte);
		return decryptedText;
	}

	public static void Keys(final byte[] key) {
        if (key == null)
            throw new RuntimeException("Invalid key: Key was null");
        if (key.length < 16)
            throw new RuntimeException("Invalid key: Length was less than 16 bytes");
        for (int off = 0, i = 0; i < 4; i++) {
            S[i] = ((key[off++] & 0xff)) | ((key[off++] & 0xff) << 8) | ((key[off++] & 0xff) << 16)
                    | ((key[off++] & 0xff) << 24);
        }
    }

    public static byte[] Tencrypt(final byte[] clear) {
        final int paddedSize = ((clear.length / 8) + (((clear.length % 8) == 0) ? 0 : 1)) * 2;
        final int[] buffer = new int[paddedSize + 1];
        buffer[0] = clear.length;
        pack(clear, buffer, 1);
        brew(buffer);
        return unpack(buffer, 0, buffer.length * 4);
    }

    public static byte[] Tdecrypt(final byte[] crypt) {
        assert crypt.length % 4 == 0;
        assert (crypt.length / 4) % 2 == 1;
        final int[] buffer = new int[crypt.length / 4];
        pack(crypt, buffer, 0);
        unbrew(buffer);
        return unpack(buffer, 1, buffer[0]);
    }

   public static void  brew(final int[] buf) {
        assert buf.length % 2 == 1;
        int i, v0, v1, sum, n;
        i = 1;
        while (i < buf.length) {
            n = CUPS;
            v0 = buf[i];
            v1 = buf[i + 1];
            sum = 0;
            while (n-- > 0) {
                sum += SUGAR;
                v0 += ((v1 << 4) + S[0] ^ v1) + (sum ^ (v1 >>> 5)) + S[1];
                v1 += ((v0 << 4) + S[2] ^ v0) + (sum ^ (v0 >>> 5)) + S[3];
            }
            buf[i] = v0;
            buf[i + 1] = v1;
            i += 2;
        }
    }

   public static void  unbrew(final int[] buf) {
        assert buf.length % 2 == 1;
        int i, v0, v1, sum, n;
        i = 1;
        while (i < buf.length) {
            n = CUPS;
            v0 = buf[i];
            v1 = buf[i + 1];
            sum = UNSUGAR;
            while (n-- > 0) {
                v1 -= ((v0 << 4) + S[2] ^ v0) + (sum ^ (v0 >>> 5)) + S[3];
                v0 -= ((v1 << 4) + S[0] ^ v1) + (sum ^ (v1 >>> 5)) + S[1];
                sum -= SUGAR;
            }
            buf[i] = v0;
            buf[i + 1] = v1;
            i += 2;
        }
    }

  public static  void pack(final byte[] src, final int[] dest, final int destOffset) {
        assert destOffset + (src.length / 4) <= dest.length;
        int i = 0, shift = 24;
        int j = destOffset;
        dest[j] = 0;
        while (i < src.length) {
            dest[j] |= ((src[i] & 0xff) << shift);
            if (shift == 0) {
                shift = 24;
                j++;
                if (j < dest.length)
                    dest[j] = 0;
            } else {
                shift -= 8;
            }
            i++;
        }
    }

  public static  byte[] unpack(final int[] src, final int srcOffset, final int destLength) {
        assert destLength <= (src.length - srcOffset) * 4;
        final byte[] dest = new byte[destLength];
        int i = srcOffset;
        int count = 0;
        for (int j = 0; j < destLength; j++) {
            dest[j] = (byte) ((src[i] >> (24 - (8 * count))) & 0xff);
            count++;
            if (count == 4) {
                count = 0;
                i++;
            }
        }
        return dest;
    }
   public static void Tea(final String enc)
   {
	AESEncrypt.Keys("And is there honey still for tea?".getBytes());

/*
	final byte[] original = enc.getBytes();

	 Run it through the cipher... and back 
	final byte[] crypt = AESEncrypt.encrypt(original);
	String encf=new String(crypt);
	System.out.println(" "+Arrays.toString(crypt));
	System.out.println(" "+encf);
	final byte[] x1=encf.getBytes();
	System.out.println(" "+Arrays.toString(x1));

	final byte[] result = tea.decrypt(crypt);
   String decf=new String(result);
	System.out.println(" "+Arrays.toString(result));
	System.out.println(" "+decf);
	/* Ensure that all went well */
	//final String test = new String(result);
	//if (!test.equals(quote))
	//	throw new RuntimeException("Fail");

   }
}
