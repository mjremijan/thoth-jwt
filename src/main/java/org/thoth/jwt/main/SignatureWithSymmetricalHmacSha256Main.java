package org.thoth.jwt.main;

import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Michael Remijan mjremijan@yahoo.com @mjremijan
 */
public class SignatureWithSymmetricalHmacSha256Main 
{
    public static void main(String[] args) throws Exception 
    {
        // JWT HEADER
        //
        // This is the xxxxx of a JWT xxxxx.yyyyy.zzzzz
        //
        // Given the following JSON document, encode it
        // using Java as defined in the JWT specifications
        String header = "{\"alg\":\"HS256\",\"typ\": \"JWT\"}";
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
        
    
        // SIGNATURE / VERIFY
        // This is the zzzzz of a JWT xxxxx.yyyyy.zzzzz
        //
        // Hash-based message authentication code(HMAC)
        // is a specific type of message authentication code 
        // (MAC) involving a cryptographic hash function and 
        // a secret cryptographic key. As with any MAC, it 
        // may be used to simultaneously verify both the data
        // integrity and authenticity of a message.
        // 
        // A cryptographic hash function (CHF) is any function 
        // that can be used to map data of arbitrary size to 
        // a fixed-size number of n bits that has special 
        // properties desirable for a cryptographic application.
        //
        // For this example, the process will use the SHA256
        // cryptographic hash function and a secret key
        // to generate a signatureCreatedFromThisData (hash) of the JWT data.
        // This signatureCreatedFromThisData can then be used to verify the
        // JWT data has not been tampered.
        //
        // Typically the secret key is only available on the 
        // Authentication Server. The key is used to create the 
        // signatureCreatedFromThisData for the JWT. Clients will typically make 
        // an authentication request (HTTPS) to the Authentication
        // server to verify a JWT. Clients cannot verify a JWT 
        // themselves because they do not have access to the
        // secret key. However, if a Client is 100% trusted,
        // The secret key can be shared with the Client so
        // that the Client can do its own verification. 
        // WARNING: This means the Client will also be able 
        // to make new JWTs, which can be dangerous.
        String algorithm  = "HmacSHA256";
        String secret = "thisismysupersecretkeywhichshouldonlybeontheauthenticationserver";
        SecretKeySpec key = new SecretKeySpec(secret.getBytes(), algorithm);
        Mac mac = Mac.getInstance(algorithm);
        mac.init(key);
        String signatureCreatedFromThisData 
            = headerEncoded + "." + payloadEncoded;
        String signatureEncoded 
            = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(mac.doFinal(
                            signatureCreatedFromThisData.getBytes()
                        )
                    );
        
        System.out.printf("%n");
        System.out.printf("Signature Algorithm : %s%n", algorithm);
        System.out.printf("Signature Secret    : %s%n", secret);
        System.out.printf("Signaure Encoded    :%s%n", signatureEncoded);
    }
}
