package com.encrypt.securityUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;


@Configuration
@RestController
public class SecurityUtils {

	private static final BCryptPasswordEncoder bcryptEncoder = new BCryptPasswordEncoder();
	private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
//.signWith(encryptDecryptRandomId.generateEncryptedKey(), SignatureAlgorithm.HS256)
	public static byte[] hashPassword(String password, String salt) {
		// Hash the password using bcrypt
		String bcryptHashString = bcryptEncoder.encode(password + salt);

		// Use SHA-256 to convert the bcrypt output into a 256-bit key
		try {
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			byte[] hash = sha256.digest(bcryptHashString.getBytes());
			return Arrays.copyOf(hash, 32); // Use only the first 256 bits (32 bytes)
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA-256 not available", e);
		}
	}

	   public String encrypt(String data, byte[] keyBytes) throws Exception {
	        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
	        Cipher cipher = Cipher.getInstance(ALGORITHM);

	        byte[] iv = new byte[16];
	        new SecureRandom().nextBytes(iv); // Generate a random IV
	        IvParameterSpec ivSpec = new IvParameterSpec(iv);

	        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
	        byte[] encrypted = cipher.doFinal(data.getBytes());

	        return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encrypted);
	    }

	   // Method to decrypt data using AES/CBC/PKCS5Padding
	    public String decrypt(String encryptedData, byte[] keyBytes) throws Exception {
	        String[] parts = encryptedData.split(":");

	        byte[] iv = Base64.getDecoder().decode(parts[0].trim()); 
	        byte[] cipherText = Base64.getDecoder().decode(parts[1].trim());

	        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
	        Cipher cipher = Cipher.getInstance(ALGORITHM);
	        IvParameterSpec ivSpec = new IvParameterSpec(iv);

	        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
	        byte[] decrypted = cipher.doFinal(cipherText);

	        return new String(decrypted);
	    }


	@GetMapping("/sec")
	public String Security() {
		String password = "securePassword"; // This should be securely obtained
		String salt = "secureSalt"; // This should be securely generated and stored
		byte[] key = hashPassword(password, salt);
		return Base64.getEncoder().encodeToString(key);
		 
	}

	@GetMapping("/")
	 public String encryptEndpoint(@RequestParam(name = "pass") String pass) {
        try {
            byte[] ds = Base64.getDecoder().decode(pass);
            String data = "1234";
            String enc = encrypt(data, ds);
            System.out.println("Encrypted: " + enc);
            return enc;
        } catch (Exception e) {
            return "Error during encryption: " + e.getMessage();
        }
    }

	@GetMapping("/gt")
	public String decrypts(@RequestParam(name = "enc") String enc,@RequestParam(name = "pass") String pass) throws Exception {
		try {
		byte[] ds = Base64.getDecoder().decode(pass);
		String dec = decrypt(enc,ds);
		System.out.println(dec);
		return dec;
		// decryptRandomId(enc);
		} catch (Exception e) {
            return "Error during encryption: " + e.getMessage();
        }
		
	}

//    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
//
//    public String encrypt(String data, byte[] keyBytes) throws Exception {
//        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//
//        byte[] iv = new byte[16];
//        new SecureRandom().nextBytes(iv); // Generate a random IV
//        IvParameterSpec ivSpec = new IvParameterSpec(iv);
//
//        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
//        byte[] encrypted = cipher.doFinal(data.getBytes());
//
//        return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encrypted);
//    }
//
//    public String decrypt(String encryptedData, byte[] keyBytes) throws Exception {
//        String[] parts = encryptedData.split(":");
//
//        byte[] iv = Base64.getDecoder().decode(parts[0]);
//        byte[] cipherText = Base64.getDecoder().decode(parts[1]);
//
//        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        IvParameterSpec ivSpec = new IvParameterSpec(iv);
//
//        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
//        byte[] decrypted = cipher.doFinal(cipherText);
//
//        return new String(decrypted);
//    }
//	

	public String encryptRandomIdGeneration() throws Exception {
		try {
			UUID randomUUID = UUID.randomUUID();
			String randomUUIDString = randomUUID.toString();
			String combinedString = randomUUIDString + "wewrewrwrew";
			SecretKeySpec keySpec = new SecretKeySpec("aithentrandomkey".getBytes(), "AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec);
			byte[] encryptedBytes = cipher.doFinal(combinedString.getBytes());
			return Base64.getEncoder().withoutPadding().encodeToString(encryptedBytes);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public String decryptRandomId(String encryptedRandomId) {
		String decryptedString = "";
		try {
			SecretKeySpec keySpec = new SecretKeySpec("aithentrandomkey".getBytes(), "AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, keySpec);
			byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedRandomId));
			decryptedString = new String(decryptedBytes);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		return decryptedString;
	}

	@Bean
	protected SecurityFilterChain configure(HttpSecurity http) throws Exception {
		http.sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		return http.build();
	}

}
