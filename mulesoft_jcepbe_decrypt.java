import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * An example class to decrypt a MuleSoft JCE encrypted PBE text.
 */
public class JEncrytion
{
    private static final String PASSWORD = "azerty34";
    private static final String ALGORITHM = "PBEWITHHMACSHA256ANDAES_128";
    private static final String DECRYPT = "bEimOZ7qSoAd1NvoTNypIA==";

    /**
     * Check JCE and Unlimited Strength Jurisdiction Policy Files
     */
    public static boolean isJCEInstalled() {
        try {
            int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
            return (maxKeyLen > 256);
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }

    /**
     * main
     */
    public static void main(String[] argv) {
        // Check JCE and Unlimited Strength Jurisdiction Policy Files
        if (!isJCEInstalled()) {
            System.out.println("You need to install the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files");
            System.exit(0);
        }

        System.out.println("Algorithm : " + ALGORITHM);
        System.out.println("Password : " + PASSWORD);

        try{
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            byte[] toDecryptByte = Base64.getDecoder().decode(DECRYPT); // From Base64 to byte

            // Key instantiation
            final PBEKeySpec keySpec = new PBEKeySpec(PASSWORD.toCharArray());
            final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
            Key key =  keyFactory.generateSecret(keySpec);

            // From ivParam to PBEParameterSpec
            byte[] ivInByteArray = new byte[cipher.getBlockSize()];
            ivInByteArray = Arrays.copyOfRange(key.getEncoded(), 0, ivInByteArray.length);
            IvParameterSpec ivParam = new IvParameterSpec(ivInByteArray);
            AlgorithmParameterSpec pbeParameter = new PBEParameterSpec("12345678".getBytes(), 20, ivParam); // Fucking hard coded 12345678 !!!!!!

            // secureRandom
            SecureRandom secureRandom = new SecureRandom();

            // cipher
            cipher.init(Cipher.DECRYPT_MODE, key, pbeParameter, secureRandom);

            System.out.println("Text Encryted : " + DECRYPT);
            System.out.println("Text Encryted (Byte Format) : " + toDecryptByte);

            // Decrypt the text
             byte[] textDecrypted = cipher.doFinal(toDecryptByte);

             System.out.println("Text Decryted : " + new String(textDecrypted));
        } catch(NoSuchAlgorithmException e){
            e.printStackTrace();
        } catch(NoSuchPaddingException e){
            e.printStackTrace();
        } catch(InvalidKeyException e){
            e.printStackTrace();
        } catch(IllegalBlockSizeException e){
            e.printStackTrace();
        } catch(InvalidKeySpecException e){
            e.printStackTrace();
        } catch(BadPaddingException e){
            e.printStackTrace();
        } catch(InvalidAlgorithmParameterException e){
            e.printStackTrace();
        }
    }
}