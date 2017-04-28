import java.io.FileInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;


public class SymmetricAsymmetric {

 public static void main(String[] args) throws Exception { 

	  String passpfx = null;
	  Map<String, String> newenv= new HashMap<String, String>();
	  String chiave = null;
	  String val = null;
	    
	  chiave = "ASTBA10-" + System.currentTimeMillis();
	  val = "Password123";
	  
	  newenv= new HashMap<String, String>();
	  
	  newenv.put(chiave, val);
	  setEnv(newenv);
	 	 
  //Generate Symmetric key
  KeyGenerator generator = KeyGenerator.getInstance("AES");
  generator.init(128);
  SecretKey key = generator.generateKey();
  byte[] symmetricKey =key.getEncoded();
  System.out.println("key : "+symmetricKey);
  
  Map<String, String> env = System.getenv();
  for (String envName : env.keySet()) {
	  if (envName.hashCode() == chiave.hashCode()) {
	  System.out.format("%s=%s%n",
                        envName,
                        env.get(envName));
	  passpfx = env.get(envName);
	  break;
	  }
  }
 /* originale 
  //Generate private key public key pair
  KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
  keyPairGenerator.initialize(1024);
  KeyPair keyPair = keyPairGenerator.generateKeyPair();
  PrivateKey privateKey = keyPair.getPrivate();
  PublicKey publicKey = keyPair.getPublic();
*/
//------------------------------------------------------------------------------
  byte [] tempPub = null;
  String sPub = null;  
  // The source of randomness
  //SecureRandom secureRandom = new SecureRandom();

//---------------------------------------
  KeyStore ks = KeyStore.getInstance("pkcs12", "SunJSSE");
  
  ks.load(new FileInputStream("C:\\OpenSSL\\bin\\demoCA\\DEKM.pfx"),passpfx.toCharArray());
   
  //X509Certificate cert = (X509Certificate) ks.getCertificate("1");
   
   
  //Key key = ks.getKey("1", "20574e47503fdde0".toCharArray());
  
  
  
  String alias = ks.aliases().nextElement();
  Key keyCert = ks.getKey(alias, passpfx.toCharArray());
  Certificate[] cc = ks.getCertificateChain(alias);

   
  //Certificate[] cc = ks.getCertificateChain("1");
   
  System.out.println("Certificate length :"+cc.length);
   
  System.out.println("Certificate 1 :"+cc[0].toString());
  
  System.out.println("Certificate 2 :"+cc[1].toString());
   
  X509Certificate certificate1 = (X509Certificate) cc[0];
  
  System.out.println("***********************************************");
   
  System.out.println("Certificate 1 Not after :"+certificate1.getNotAfter());
   
  System.out.println("Certificate 1 Not before :"+certificate1.getNotBefore());
   
  System.out.println("***********************************************");
   
  //System.out.println("Certificate 2 :"+cc[1].toString());
   
  X509Certificate certificate2 = (X509Certificate) cc[1];
   
  System.out.println("Certificate 2 Not after :"+certificate2.getNotAfter());
   
  System.out.println("Certificate 2 Not before :"+certificate2.getNotBefore());
  
  System.out.println("***********************************************");
//---------------------------------------  
  
  // Obtain a RSA Cipher Object
  //Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); //,"BC");    
                  
  // Loading certificate file  
  //String certFile = "C:\\OpenSSL\\bin\\demoCA\\cacert.pem";
  // 1 String certFile = "C:\\OpenSSL\\bin\\demoCA\\tomcat.cer";
  String certFile = "C:\\OpenSSL\\bin\\demoCA\\DEKM_nokey.pem";
  
  InputStream inStream = new FileInputStream(certFile);
  CertificateFactory cf = CertificateFactory.getInstance("X.509");
  X509Certificate cert =(X509Certificate)cf.generateCertificate(inStream);
  inStream.close();

  // Read the public key from certificate file
  RSAPublicKey publicKey = (RSAPublicKey) certificate1.getPublicKey(); // cert.getPublicKey();
  System.out.println(publicKey.getModulus().bitLength());
  tempPub = publicKey.getEncoded();
  sPub = new String( tempPub );
 // System.out.println("Public key from certificate file:\n" + hex(sPub) + "\n");
  System.out.println("Public Key Algorithm = " + publicKey.getAlgorithm() + "\n" );

  
  //------------------------
  // get Private Key from PFX
  
  PrivateKey privateKey=null;
  privateKey=getPrivateKeyFromPFX(ks,passpfx);
  
  
  //------------------------  
  
  /*
  // Loading private key file  
  //String keyFile = "C:\\OpenSSL\\bin\\demoCA\\private\\cakey.p8c";
  // 1 String keyFile = "C:\\OpenSSL\\bin\\demoCA\\private\\tomcatcakey.p8c";
  String keyFile = "C:\\OpenSSL\\bin\\demoCA\\private\\DEKM_private.p8c";
  inStream=new FileInputStream(keyFile);
  byte[] encKey=new byte[inStream.available()];
  inStream.read(encKey);
  inStream.close();
  
  // Read the private key from file
  
  System.out.println("RSA PrivateKeyInfo: " + encKey.length + " bytes\n") ;
  PKCS8EncodedKeySpec privKeySpec=new PKCS8EncodedKeySpec(encKey);
  KeyFactory keyFactory = KeyFactory.getInstance("RSA");
  System.out.println("KeyFactory Object Info:");
  System.out.println("Algorithm = "+keyFactory.getAlgorithm());
  System.out.println("Provider = "+keyFactory.getProvider());     
  PrivateKey privateKey= (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);
  System.out.println("Loaded " + privateKey.getAlgorithm() + " " + privateKey.getFormat() + " private key.");
*/
  
  
  // Set plain message
  String message = "IN DATA ODIERNA SI E' PRESENTATA LA SIGNORA MARILLI RITA SORELLA DEL SIGNOR MARILLI VITTORIO RIFERENDO QUANTO SEGUE: IL SIGNOR VITTORIO, VIVE SOLO, IN UN'ABITAZIONE DI PROPRIETA'." +
  			"DAL PUNTO DI VISTA FAMILIARE, L'UTENTE E' SUPPORTATA DA TUTTI I FRATELLI. DAL PUNTO DI VISTA ECONOMICO, L'ANZIANO, PERCEPISCE UNA PENSIONE LAVORATIVA DI CIRCA 1.500,00€ AL MESE." +
  			"DAL PUNTO DI VISTA SANITARIO, L'UTENTE E' AFFETTO DA CARDIOPATIA E DA DEMENZA SENILE DI CIRCA DUE ANNI. LA SIGNORA RITA RIFERISCE CHE HANNO DIFFICOLTA' A GESTIRE LA MALATTIA DEL FRATELLO, PERTANTO RICHIEDONO L'INSERIMENTO PRESSO UNA RSSA. INOLTRE LA SIGNORA MARILLI DICHIARA CHE IL SIGNOR VITTORIO E' AUTONOMO AL PAGAMENTO DELLA RETTA ALBERGHIERA.";
  
  
//------------------------------------------------------------------------------  
  //Encrypt Data by symmetric key
  String encryptedData = encryptWithAESKey(message, symmetricKey);
  System.out.println("Encrypted Data : " + encryptedData);
  //Encrypt symmetric key by public key
  Cipher cipher = Cipher.getInstance("RSA");
//  
  cipher.init(Cipher.ENCRYPT_MODE, publicKey);
  String encryptedkey =Base64.encodeBase64String(cipher.doFinal(symmetricKey));
  
  //Send message and key to other user having private key
  
  //Decrypt symmetric Key by private key
  Cipher dipher = Cipher.getInstance("RSA");
  dipher.init(Cipher.DECRYPT_MODE, privateKey);
  byte[] decryptedSymmetricKey =dipher.doFinal(Base64.decodeBase64(encryptedkey));
  
  //Decrypt encrypted Data by decrypted symmetric key
  System.out.println("Decrypted Data : " +decryptWithAESKey(encryptedData, decryptedSymmetricKey));

 }



 public static String encryptWithAESKey(String data, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException,
   InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
  SecretKey secKey = new SecretKeySpec(key,"AES");

  Cipher cipher = Cipher.getInstance("AES");
  
  cipher.init(Cipher.ENCRYPT_MODE, secKey);
  byte[] newData = cipher.doFinal(data.getBytes());
  
  return Base64.encodeBase64String(newData);
 }

 public static String decryptWithAESKey(String inputData, byte[] key) throws NoSuchAlgorithmException,
   NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
  Cipher cipher = Cipher.getInstance("AES");
  SecretKey secKey = new SecretKeySpec(key, "AES");

  cipher.init(Cipher.DECRYPT_MODE, secKey);
  byte[] newData = cipher.doFinal(Base64.decodeBase64(inputData.getBytes()));
  return new String(newData);

 }

 /**
  * Get the private key from a KeyStore in PKCS#12 format (*.PFX created
  * by Microsoft IE/OE and others)
  */
 public static PrivateKey getPrivateKeyFromPFX(KeyStore ks, String pwd) {
     try {
        /// FileInputStream fis = new FileInputStream(keyStore);
         // supported KeyStore types (JDK1.4): PKCS12 and JKS (native Sun)
        /// KeyStore ks = KeyStore.getInstance("PKCS12");
        /// ks.load(fis, password);
    	 char[] password= pwd.toCharArray();
         for (Enumeration<String> en=ks.aliases(); en.hasMoreElements(); ) {
             String alias = (String)en.nextElement();
	             if (ks.isKeyEntry(alias)) {
	                 return (PrivateKey)ks.getKey(alias, password);
	             }
         }
     } catch (Exception ex) {
    	 System.out.println("Error in retrieving pivate key!");
     }
     return null;        
 } 
 
 protected static void setEnv(Map<String, String> newenv)
 {
   try
     {
         Class<?> processEnvironmentClass = Class.forName("java.lang.ProcessEnvironment");
         Field theEnvironmentField = processEnvironmentClass.getDeclaredField("theEnvironment");
         theEnvironmentField.setAccessible(true);
         @SuppressWarnings("unchecked")
		Map<String, String> env = (Map<String, String>) theEnvironmentField.get(null);
         env.putAll(newenv);
         Field theCaseInsensitiveEnvironmentField = processEnvironmentClass.getDeclaredField("theCaseInsensitiveEnvironment");
         theCaseInsensitiveEnvironmentField.setAccessible(true);
         @SuppressWarnings("unchecked")
		Map<String, String> cienv = (Map<String, String>)     theCaseInsensitiveEnvironmentField.get(null);
         cienv.putAll(newenv);
     }
     catch (NoSuchFieldException e)
     {
       try {
         Class[] classes = Collections.class.getDeclaredClasses();
         Map<String, String> env = System.getenv();
         for(Class cl : classes) {
             if("java.util.Collections$UnmodifiableMap".equals(cl.getName())) {
                 Field field = cl.getDeclaredField("m");
                 field.setAccessible(true);
                 Object obj = field.get(env);
                 Map<String, String> map = (Map<String, String>) obj;
                 map.clear();
                 map.putAll(newenv);
             }
         }
       } catch (Exception e2) {
         e2.printStackTrace();
       }
     } catch (Exception e1) {
         e1.printStackTrace();
     } 
 }
}