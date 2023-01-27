package org.thoth.jwt;

import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.net.URLEncoder;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author mjrem
 */
public class JwtSHA256withHMACMain {

    public static void main(String[] args) throws Exception {
        new JwtSHA256withHMACMain().main();
    }

    public void main() throws Exception {
        
        String secret = "thisismysupersecretkeywhichshouldonlybeontheauthenticationserver";
        String algorithm  = "HmacSHA256";
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(), algorithm);

        String encodedSecretKey = Base64.getEncoder().encodeToString(secretKeySpec.getEncoded());
        System.out.println("Secret Key:");
        System.out.println(convertToSecretKey(encodedSecretKey));
        String token = generateJwtToken(secretKeySpec);
        System.out.println("TOKEN:");
        System.out.println(token);
        String[] tokens = token.split("\\.");
        String jwtHeader = tokens[0];
        String jwtPayload = tokens[1];
        String jwtSignature = tokens[2];
        System.out.printf("Header     : %s%n", jwtHeader);
        System.out.printf("Body       : %s%n", jwtPayload);
        System.out.printf("Signature  : %s%n", jwtSignature);
        System.out.printf("---%n");
        printStructure(token, secretKeySpec);
        
        
        // MINE
        System.out.printf("%nMINE:%n");
        // HEADER 
        System.out.printf("--HEADER%n");
        {
            String headerFromExampleEncoded = "eyJhbGciOiJIUzI1NiJ9";
            String headerFromExampleDecoded = new String(Base64.getUrlDecoder().decode(headerFromExampleEncoded));
            System.out.printf("%-30s: %s%n", "headerFromExampleDecoded", headerFromExampleDecoded);
        }
        String myEncodedHeader = null;
        {
            // actual
            System.out.printf("%-30s: %s%n", "jwtHeader", jwtHeader);
            
            String headerFromExampleDecoded = "{\"alg\":\"HS256\"}";
            // 1
            String myHeaderEncoding1 = Base64.getUrlEncoder().encodeToString(headerFromExampleDecoded.getBytes());
            System.out.printf("%-30s: %s  %b%n", "myHeaderEncoding1", myHeaderEncoding1, jwtHeader.equals(myHeaderEncoding1));
            // 2
            String myHeaderEncoding2 = URLEncoder.encode(Base64.getEncoder().encodeToString(headerFromExampleDecoded.getBytes()), "utf-8");
            System.out.printf("%-30s: %s  %b%n", "myHeaderEncoding2", myHeaderEncoding2, jwtHeader.equals(myHeaderEncoding2));
            // 3
            String myHeaderEncoding3 = Base64.getUrlEncoder().withoutPadding().encodeToString(headerFromExampleDecoded.getBytes());
            System.out.printf("%-30s: %s  %b%n", "myHeaderEncoding3", myHeaderEncoding3, jwtHeader.equals(myHeaderEncoding3));
            
            myEncodedHeader = myHeaderEncoding3;
        }
        // PAYLOAD
        System.out.printf("--PAYLOAD%n");        
        {
            String payloadFromExampleEncoded = "eyJzdWIiOiJhZGFtIiwiZXhwIjo2MTQ3NTYwODgwMCwiaXNzIjoiaW5mb0B3c3R1dG9yaWFsLmNvbSIsImdyb3VwcyI6WyJ1c2VyIiwiYWRtaW4iXX0";
            String payloadFromExampleDecoded = new String(Base64.getUrlDecoder().decode(payloadFromExampleEncoded));
            System.out.printf("%-30s: %s%n", "payloadFromExampleDecoded", payloadFromExampleDecoded);
        }
        String myEncodedPayload = null;
        {
            // actual
            System.out.printf("%-30s: %s%n", "jwtPayload", jwtPayload);
            
            String payloadFromExampleDecoded = "{\"sub\":\"adam\",\"exp\":61475608800,\"iss\":\"info@wstutorial.com\",\"groups\":[\"user\",\"admin\"]}";
            // 1
            String myPayloadEncoding1 = Base64.getUrlEncoder().encodeToString(payloadFromExampleDecoded.getBytes());
            System.out.printf("%-30s: %s  %b%n", "myPayloadEncoding1", myPayloadEncoding1, jwtPayload.equals(myPayloadEncoding1));
            // 2
            String myPayloadEncoding2 = URLEncoder.encode(Base64.getEncoder().encodeToString(payloadFromExampleDecoded.getBytes()), "utf-8");
            System.out.printf("%-30s: %s  %b%n", "myPayloadEncoding2", myPayloadEncoding2, jwtPayload.equals(myPayloadEncoding2));
            // 3
            String myPayloadEncoding3 = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadFromExampleDecoded.getBytes());
            System.out.printf("%-30s: %s  %b%n", "myPayloadEncoding3", myPayloadEncoding3, jwtPayload.equals(myPayloadEncoding3));
            
            myEncodedPayload = myPayloadEncoding3;
        }
        
        
        // SIGNATURE
        System.out.printf("--SIGNATURE%n"); 
        String myEncodedSignature = null;
        {
            // actual
            System.out.printf("%-30s: %s%n", "jwtSignature", jwtSignature);
            
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKeySpec);
            byte[] signature = mac.doFinal((myEncodedHeader + "." + myEncodedPayload).getBytes());
            // 1
            String mySignatueEncoding1 = Base64.getUrlEncoder().encodeToString(signature);           
            System.out.printf("%-30s: %s  %b%n", "mySignatueEncoding1", mySignatueEncoding1, jwtSignature.equals(mySignatueEncoding1));
            // 2
            String mySignatueEncoding2 = URLEncoder.encode(Base64.getEncoder().encodeToString(signature), "utf-8");        
            System.out.printf("%-30s: %s  %b%n", "mySignatueEncoding2", mySignatueEncoding2, jwtSignature.equals(mySignatueEncoding2));
            // 3
            String mySignatueEncoding3 = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
            System.out.printf("%-30s: %s  %b%n", "mySignatueEncoding3", mySignatueEncoding3, jwtSignature.equals(mySignatueEncoding3));                        
            
            myEncodedSignature = mySignatueEncoding3;
        }
        
        // VERIFY
        {
            // Since HMAC is a symmetric algorithm,
            // the SIGNATURE step and the VERIFY
            // step are the same. If a Client wanted
            // to verify the JWT, the Client would need
            // the `String secret = ...` above to do
            // it. However, this secret value should
            // only be known to the Authenication Server.
            // Thus, in an HMAC scenario, the Client
            // would need to make a verification call
            // to the Authentication Server for the 
            // Authenticaiton Server to verify the JWT.
            // Or, if the client is 100% trusted, the
            // `String secret = ...` may be shared with
            // the Client.
        }
    }

    public String generateJwtToken(Key key) {
        String token = 
                Jwts.builder().setSubject("adam")
                .setExpiration(new Date(2018, 1, 1))
                .setIssuer("info@wstutorial.com")
                .claim("groups", new String[]{"user", "admin"})
                // HS256 
                .signWith(SignatureAlgorithm.HS256, key)
                .compact();
        return token;
    }

    //Print structure of JWT
    public void printStructure(String token, Key key) {
        Jws parseClaimsJws = Jwts.parser().setSigningKey(key)
                .parseClaimsJws(token);

        System.out.println("Header     : " + parseClaimsJws.getHeader());
        System.out.println("Body       : " + parseClaimsJws.getBody());
        System.out.println("Signature  : " + parseClaimsJws.getSignature());
    }

    // Add BEGIN and END comments
    private String convertToSecretKey(String key) {
        StringBuilder result = new StringBuilder();
        result.append("-----BEGIN MY SECRET KEY-----\n");
        result.append(key);
        result.append("\n-----END MY SECRET KEY-----");
        return result.toString();
    }
}
