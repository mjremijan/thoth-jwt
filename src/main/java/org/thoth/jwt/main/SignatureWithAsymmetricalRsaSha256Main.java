package org.thoth.jwt.main;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 *
 * @author Michael Remijan mjremijan@yahoo.com @mjremijan
 */
public class SignatureWithAsymmetricalRsaSha256Main 
{
    public static void main(String[] args) throws Exception 
    {
        // JWT HEADER
        //
        // This is the xxxxx of a JWT xxxxx.yyyyy.zzzzz
        //
        // Given the following JSON document, encode it
        // using Java as defined in the JWT specifications
        String header = "{\"alg\":\"RS256\",\"typ\": \"JWT\"}";
        String headerEncoded 
            = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(
                        header.getBytes()
                    );
        String headerDecoded
                = new String(
                    Base64.getUrlDecoder().decode(headerEncoded)
                );
        
        System.out.printf("Header Plain   : %s%n", header);
        System.out.printf("Header Encoded : %s%n", headerEncoded);
        System.out.printf("Header Decoded : %s%n", headerDecoded);
        
        
        // JWT PAYLOAD
        //
        // This is the yyyyy of a JWT xxxxx.yyyyy.zzzzz
        //
        // Given the following JSON document, encode it
        // using Java as defined in the JWT specifications
        String payload = "{\"sub\":\"TMJR00001\",\"name\":\"Michael J. Remijan\",\"exp\":61475608800,\"iss\":\"info@wstutorial.com\",\"groups\":[\"user\",\"admin\"]}";
        String payloadEncoded 
            = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(
                        payload.getBytes()
                    );
        
        String payloadDecoded
                = new String(
                    Base64.getUrlDecoder().decode(payloadEncoded)
                );
        
        System.out.printf("%n");
        System.out.printf("Payload Plain   : %s%n", payload);
        System.out.printf("Payload Encoded : %s%n", payloadEncoded);
        System.out.printf("Payload Decoded : %s%n", payloadDecoded);
        
    
        // SIGNATURE
        //
        // This is the zzzzz of a JWT xxxxx.yyyyy.zzzzz
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
        String algorithm = "SHA256withRSA";
        String signatureCreatedFromThisData 
            = headerEncoded + "." + headerDecoded;
        
        Signature privateSignature 
            = Signature.getInstance(algorithm);
        privateSignature.initSign(privateKey);
        
        System.out.printf("%n");
        System.out.printf("Algorithm    : %s%n", algorithm);
        System.out.printf("Public Key   : %s%n", Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.printf("Private Key  : %s%n", Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        
        privateSignature.update(signatureCreatedFromThisData.getBytes());
        String signatureEncoded 
                = Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                            privateSignature.sign()
                        );
        System.out.printf("%n");
        System.out.printf("Signaure Encoded         : %s%n", signatureEncoded);
        
        // VERIFY
        // This is the zzzzz of a JWT xxxxx.yyyyy.zzzzz
        //
        // The public key is used for verifying the signature.
        //
        // Becuase the public key is used for creating a signature,
        // it safe to distribute the public key to Clients so 
        // that Clients can verify the JWT signature without
        // having to ask the Authentication Server for verification
        //
        
        Signature publicSignature = Signature.getInstance(algorithm);
        publicSignature.initVerify(publicKey);
        publicSignature.update(signatureCreatedFromThisData.getBytes());
        boolean verified = publicSignature.verify(
            Base64.getUrlDecoder().decode(signatureEncoded)
        );
        System.out.printf("Signature Verified (t/f) : %b%n", verified);
    }
}
