//dcrypt22
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.*;

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {
    public final static int SALT_LEN     = 8;
    static final String     HEXES        = "0123456789ABCDEF";
    String                  pwd    = null;
    byte[]                  initialVector     = null;
    byte[]                  salt        = new byte[SALT_LEN];
    Cipher                  encryptedCipher     = null;
    Cipher                  decryptedCipher    = null;
    private final int       KEYLEN_BITS  = 128;    
    private final int       ITERATIONS   = 65536;
    private final int       MAX_FILE_BUF = 1024;

    /**

     * @param password
     */
    public AES(String password) {
        pwd = password;
    }

    public static String byteToHex(byte[] raw) {
        if (raw == null) {
            return null;
        }

        final StringBuilder hex = new StringBuilder(2 * raw.length);

        for (final byte b : raw) {
            hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
        }

        return hex.toString();
    }

    public static byte[] hexToByte(String hexString) {
        int    len = hexString.length();
        byte[] ba  = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            ba[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                                + Character.digit(hexString.charAt(i + 1), 16));
        }

        return ba;
    }

    /**
     * debug/print messages
     * @param msg
     */
    private void Db(String msg) {
        System.out.println("** encrypting ** " + msg);
    }

    /**
 
     *
     * @param input - the cleartext file to be encrypted
     * @param output - the encrypted data file
     * @throws IOException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public void WriteEncryptedFile(InputStream inputStream, OutputStream outputStream)
            throws IOException, IllegalBlockSizeException, BadPaddingException {
        try {
            long             totalread = 0;
            int              nread     = 0;
            byte[]           inbuf     = new byte[MAX_FILE_BUF];
            SecretKeyFactory factory   = null;
            SecretKey        tmp       = null;

            // crate secureRandom salt and store  as member var for later use
            salt = new byte[SALT_LEN];

            SecureRandom rnd = new SecureRandom();

            rnd.nextBytes(salt);
            Db("generated salt :" + byteToHex(salt));
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        
           
            KeySpec spec = new PBEKeySpec(pwd.toCharArray(), salt, ITERATIONS, KEYLEN_BITS);

            tmp = factory.generateSecret(spec);

            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

          
            encryptedCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            encryptedCipher.init(Cipher.ENCRYPT_MODE, secret);

            AlgorithmParameters params = encryptedCipher.getParameters();

            initialVector = params.getParameterSpec(IvParameterSpec.class).getIV();
            Db("initialVector is :" + byteToHex(initialVector));
            outputStream.write(salt);
            outputStream.write(initialVector);

            while ((nread = inputStream.read(inbuf)) > 0) {
                Db("read " + nread + " bytes");
                totalread += nread;

                byte[] trimbuf = new byte[nread];

                for (int i = 0; i < nread; i++) {
                    trimbuf[i] = inbuf[i];
                }

                
                byte[] tmpBuf = encryptedCipher.update(trimbuf);

            
                if (tmpBuf != null) {
                    outputStream.write(tmpBuf);
                }
            }

            byte[] finalbuf = encryptedCipher.doFinal();

            if (finalbuf != null) {
                outputStream.write(finalbuf);
            }

            outputStream.flush();
            inputStream.close();
            outputStream.close();
            outputStream.close();
            Db("wrote " + totalread + " encrypted bytes");
        } catch (InvalidKeyException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidParameterSpecException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     *
     * @param input 
     * @param output 
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     */
    public void ReadEncryptedFile(InputStream inputStream, OutputStream outputStream)
            throws IllegalBlockSizeException, BadPaddingException, IOException {
        try {
            CipherInputStream cin;
            long              totalread = 0;
            int               nread     = 0;
            byte[]            inbuf     = new byte[MAX_FILE_BUF];

            // Read the Salt
            inputStream.read(this.salt);
            Db("generated salt :" + byteToHex(salt));

            SecretKeyFactory factory = null;
            SecretKey        tmp     = null;
            SecretKey        secret  = null;

            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

            KeySpec spec = new PBEKeySpec(pwd.toCharArray(), salt, ITERATIONS, KEYLEN_BITS);

            tmp    = factory.generateSecret(spec);
            secret = new SecretKeySpec(tmp.getEncoded(), "AES");

       
            decryptedCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            
            AlgorithmParameters params = decryptedCipher.getParameters();

            initialVector = params.getParameterSpec(IvParameterSpec.class).getIV();

           
            inputStream.read(this.initialVector);
            Db("initial Vector is :" + byteToHex(initialVector));
            decryptedCipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(initialVector));

            cin = new CipherInputStream(inputStream, decryptedCipher);

            while ((nread = cin.read(inbuf)) > 0) {
                Db("read " + nread + " bytes");
                totalread += nread;

              
                byte[] trimbuf = new byte[nread];

                for (int i = 0; i < nread; i++) {
                    trimbuf[i] = inbuf[i];
                }

            
                outputStream.write(trimbuf);
            }

            outputStream.flush();
            cin.close();
            inputStream.close();
            outputStream.close();
            Db("wrote " + totalread + " encrypted bytes");
        } catch (Exception ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

  
    public static void main(String[] args) {

        File   input   = new File("file.txt");
        File   eoutput = new File("encrypted.aes");
        File   doutput = new File("decrypted.txt");
        String iv      = null;
        String salt    = null;
        AES    en      = new AES("mypassword");

        try {
            en.WriteEncryptedFile(new FileInputStream(input), new FileOutputStream(eoutput));
            System.out.printf("File encrypted to " + eoutput.getName() + "\niv:" + iv + "\nsalt:" + salt + "\n\n");
        } catch (IllegalBlockSizeException | BadPaddingException | IOException e) {
            e.printStackTrace();
        }

 
        AES dc = new AES("mypassword");


        try {
            dc.ReadEncryptedFile(new FileInputStream(eoutput), new FileOutputStream(doutput));
            System.out.println("decryption finished to " + doutput.getName());
        } catch (IllegalBlockSizeException | BadPaddingException | IOException e) {
            e.printStackTrace();
        }
    }
}

