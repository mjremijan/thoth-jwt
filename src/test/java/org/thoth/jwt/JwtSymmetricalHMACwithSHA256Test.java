package org.thoth.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Base64;
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

/**
 *
 * @author mjrem
 */
public class JwtSymmetricalHMACwithSHA256Test {
    
    @Test
    public void testHMACwithSHA256() throws Exception
    {
        String secret = "thisismysupersecretkeywhichshouldonlybeontheauthenticationserver";
        String algorithm  = "HmacSHA256";
        SecretKeySpec key = new SecretKeySpec(secret.getBytes(), algorithm);
        
        String [] tokens = 
            Jwts.builder().setSubject("adam")
           .setExpiration(new Date(2018, 1, 1))
           .setIssuer("info@wstutorial.com")
           .claim("groups", new String[]{"user", "admin"})
           .signWith(SignatureAlgorithm.HS256, key)
           .compact().split("\\.")
        ;
        
        // HEADER
        String header = "{\"alg\":\"HS256\"}";
        String expectedEncodedHeader = tokens[0];
        String actualEncodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes());
        assertEquals(expectedEncodedHeader, actualEncodedHeader);
        
        // PAYLOAD
        String payload = "{\"sub\":\"adam\",\"exp\":61475608800,\"iss\":\"info@wstutorial.com\",\"groups\":[\"user\",\"admin\"]}";
        String expectedEncryptedPayload = tokens[1];
        String actualEncodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes());
        assertEquals(expectedEncryptedPayload, actualEncodedPayload);
        
        // SIGNATURE / VERIFY
        String expectedEncryptedSignature = tokens[2];
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        String actualEncryptedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(
            mac.doFinal((actualEncodedHeader + "." + actualEncodedPayload).getBytes())
        );
        assertEquals(expectedEncryptedSignature, actualEncryptedSignature);
    }
}
