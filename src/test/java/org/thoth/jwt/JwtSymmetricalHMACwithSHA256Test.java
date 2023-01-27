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
 * @author Michael Remijan <mjremijan@yahoo.com>
 */
public class JwtSymmetricalHMACwithSHA256Test {
    
    @Test
    public void testHMACwithSHA256() throws Exception
    {
        // This sets up an HMAC key with a secret value which 
        // should remain known only to the Authentication Server
        // and trusted clients.
        String secret = "thisismysupersecretkeywhichshouldonlybeontheauthenticationserver";
        String algorithm  = "HmacSHA256";
        SecretKeySpec key = new SecretKeySpec(secret.getBytes(), algorithm);
        
        // Here the jjwt library is used to generate a JWT. 
        // Remember a JWT is in the form of xxxx.yyyy.zzzz 
        // I'm creating this object so I can use it as the
        // an expected values for the JUnit tests.
        String [] tokens = 
            Jwts.builder().setSubject("adam")
           .setExpiration(new Date(2018, 1, 1))
           .setIssuer("info@wstutorial.com")
           .claim("groups", new String[]{"user", "admin"})
           .signWith(SignatureAlgorithm.HS256, key)
           .compact().split("\\.")
        ;
        
        // JWT HEADER
        // Given the following JSON header, encode it and 
        // assert it with the encoded header created by jjwt.
        String header = "{\"alg\":\"HS256\"}";
        String actualEncodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes());
        assertEquals(tokens[0], actualEncodedHeader);
        
        // JWT PAYLOAD
        // Given the following JSON payload, encode it and 
        // assert it with the encoded payload created by jjwt.
        String payload = "{\"sub\":\"adam\",\"exp\":61475608800,\"iss\":\"info@wstutorial.com\",\"groups\":[\"user\",\"admin\"]}";
        String actualEncodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes());
        assertEquals(tokens[1], actualEncodedPayload);
        
        // SIGNATURE / VERIFY
        // For HMAC, which is a symmetric algorithm, the
        // signature and verify steps are the same because
        // both rely on the same key (see above). The key
        // is created using a secret value (see above) and
        // this secret value must be kept secret and only
        // available on the Authentication Server. The key
        // is used to create the signature for the JWT. Clients
        // Typically will make an authentication request (HTTPS)
        // to the Authentication server to verify a JWT. Clients
        // cannot verify a JWT themselves because they do not
        // have access to the secret value used to create
        // the HMAC key. However, if a Client is 100% trusted,
        // The secret value can be shared with the Client so
        // that the Client can do its own verification. 
        // WARNING: This means the Client will also be able 
        // to make new JWTs, which can be dangerous.
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        String actualEncryptedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(
            mac.doFinal((actualEncodedHeader + "." + actualEncodedPayload).getBytes())
        );
        assertEquals(tokens[2], actualEncryptedSignature);
    }
}
