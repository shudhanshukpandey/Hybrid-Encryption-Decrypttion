

import java.io.FileReader;
public class AESENCYPDECYP {

	public static void main(String[] args) throws Exception {
		
		String plainText = "";
		FileReader fr = new FileReader("/home/unish/Desktop/originalfile.txt");
		int i;
		while((i=fr.read())!=-1)
        {
            char c = (char)i;
           plainText = plainText+ Character.toString(c);
        }
		fr.close();
		System.out.println("Plain Text Before Encryption: \n" + plainText);

		AESEncrypt.aesIni(plainText);
		


		//System.out.println("\n\n\n "+casper);
	}
}
