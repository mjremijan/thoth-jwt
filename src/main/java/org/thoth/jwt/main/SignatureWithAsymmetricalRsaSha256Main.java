package org.thoth.jwt.main;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 *
 * @author mjrem
 */
public class SignatureWithAsymmetricalRsaSha256Main {
    public static void main(String[] args) throws Exception {
        // See HeaderMain.java
        String encodedHeader 
            = "eyJhbGciOiJIUzI1NiJ9";
        
        // See PayloadMain.java
        String encodedPayload 
            = "eyJzdWIiOiJhZGFtIiwiZXhwIjo2MTQ3NTYwODgwMCwiaXNzIjoiaW5mb0B3c3R1dG9yaWFsLmNvbSIsImdyb3VwcyI6WyJ1c2VyIiwiYWRtaW4iXX0";
    
        // SIGNATURE
        // This is the zzzzz of a jwt xxxxx.yyyyy.zzzzz
        //
        // RSA (Rivest–Shamir–Adleman) is a public-key cryptosystem 
        // that is widely used for secure data transmission.
        // In a public-key cryptosystem, the public key is used for
        // encryption and the private key is used for decryption. The
        // private key is also used for creating digital signatures
        // of data and the public key is used for verifying the
        // digital signature.
        //
        // A cryptographic hash function (CHF) is any function 
        // that can be used to map data of arbitrary size to 
        // a fixed-size number of n bits that has special 
        // properties desirable for a cryptographic application.
        //
        // For this example, the process will use the SHA256
        // cryptographic hash function along with a public/private
        // keypair and the RSA encryption algorithm to generate
        // a signature for the JWT.
        //
        // The private key is used for creating the signature.
        //
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);
        KeyPair kp = keyGenerator.genKeyPair();
        PublicKey publicKey = (PublicKey) kp.getPublic();
        PrivateKey privateKey = (PrivateKey) kp.getPrivate();
        String signatureCreatedFromThisData 
            = encodedHeader + "." + encodedPayload;
        
        Signature privateSignature 
            = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(signatureCreatedFromThisData.getBytes());
        String encryptedSignature 
                = Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                            privateSignature.sign()
                        );
        System.out.printf("%s%n", encryptedSignature);
        
        // VERIFY
        // This is the zzzzz of a jwt xxxxx.yyyyy.zzzzz
        //
        // The public key is used for verifying the signature.
        //
        // Becuase the public key is used for creating a signature,
        // it safe to distribute the public key to Clients so 
        // that Clients can verify the JWT signature without
        // having to ask the Authentication Server for verification
        //
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(signatureCreatedFromThisData.getBytes());
        boolean verified = publicSignature.verify(
            Base64.getUrlDecoder().decode(encryptedSignature)
        );
        System.out.printf("%b%n", verified);
    }
}
