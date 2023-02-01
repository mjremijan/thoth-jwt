package org.thoth.jwt.main;

import java.util.Base64;

/**
 *
 * @author Michael Remijan mjremijan@yahoo.com @mjremijan
 */
public class HeaderMain {
    public static void main(String[] args) {
        // JWT HEADER
        // This is the xxxxx of a JWT xxxxx.yyyyy.zzzzz
        //
        // Given the following JSON document, encode it
        // using Java as defined in the JWT specifications
        String header = "{\"alg\":\"HS256\"}";
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
        
        System.out.printf("Header : %s%n", header);
        System.out.printf("Encoded: %s%n", headerEncoded);
        System.out.printf("Decoded: %s%n", headerDecoded);
    }
}
