package org.thoth.jwt.main;

import java.util.Base64;

/**
 *
 * @author mjrem
 */
public class HeaderMain {
    public static void main(String[] args) {
        // JWT HEADER
        // This is the xxxxx of a jwt xxxxx.yyyyy.zzzzz
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
        System.out.printf("%s%n", headerEncoded);
    }
}
