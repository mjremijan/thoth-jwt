package org.thoth.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Date;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

/**
 *
 * @author mjrem
 */
public class JwtAsymmetricalRSAwithSHA256Test {

    @Test
    public void testHMACwithSHA256() throws Exception 
    {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);
        KeyPair kp = keyGenerator.genKeyPair();
        PublicKey publicKey = (PublicKey) kp.getPublic();
        PrivateKey privateKey = (PrivateKey) kp.getPrivate();

        String[] tokens
                = Jwts.builder().setSubject("adam")
                        .setExpiration(new Date(2018, 1, 1))
                        .setIssuer("info@wstutorial.com")
                        .claim("groups", new String[]{"user", "admin"})
                        .signWith(SignatureAlgorithm.RS256, privateKey)
                        .compact().split("\\.");

        // JWT HEADER
        String header = "{\"alg\":\"RS256\"}";
        String expectedEncodedHeader = tokens[0];
        String actualEncodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes());
        assertEquals(expectedEncodedHeader, actualEncodedHeader);

        // JWT PAYLOAD
        String payload = "{\"sub\":\"adam\",\"exp\":61475608800,\"iss\":\"info@wstutorial.com\",\"groups\":[\"user\",\"admin\"]}";
        String expectedEncryptedPayload = tokens[1];
        String actualEncodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes());
        assertEquals(expectedEncryptedPayload, actualEncodedPayload);

        // JWT SIGNATURE
        String expectedEncryptedSignature = tokens[2];
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update((actualEncodedHeader + "." + actualEncodedPayload).getBytes());
        String actualEncryptedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(
                privateSignature.sign()
        );
        assertEquals(expectedEncryptedSignature, actualEncryptedSignature);

        // CLIENT VERIFY
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update((actualEncodedHeader + "." + actualEncodedPayload).getBytes());
        boolean verified = publicSignature.verify(
            Base64.getUrlDecoder().decode(actualEncryptedSignature)
        );
        assertTrue(verified);
    }
}
