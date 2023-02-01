package org.thoth.jwt.main;

import java.util.Base64;

/**
 *
 * @author Michael Remijan mjremijan@yahoo.com @mjremijan
 */
public class PayloadMain {
    public static void main(String[] args) {
        // JWT PAYLOAD
        // This is the yyyyy of a JWT xxxxx.yyyyy.zzzzz
        //
        // Given the following JSON document, encode it
        // using Java as defined in the JWT specifications
        String payload = "{\"sub\":\"adam\",\"exp\":61475608800,\"iss\":\"info@wstutorial.com\",\"groups\":[\"user\",\"admin\"]}";
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
        
        System.out.printf("Payload : %s%n", payload);
        System.out.printf("Encoded: %s%n", payloadEncoded);
        System.out.printf("Decoded: %s%n", payloadDecoded);
    }
}
