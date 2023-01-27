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
 * @author Michael Remijan <mjremijan@yahoo.com>
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
        
        // Here the jjwt library is used to generate a JWT. 
        // Remember a JWT is in the form of xxxx.yyyy.zzzz 
        // I'm creating this object so I can use it as the
        // an expected values for the JUnit tests.
        String[] tokens = 
             Jwts.builder().setSubject("adam")
            .setExpiration(new Date(2018, 1, 1))
            .setIssuer("info@wstutorial.com")
            .claim("groups", new String[]{"user", "admin"})
            .signWith(SignatureAlgorithm.RS256, privateKey)
            .compact().split("\\.");

        // JWT HEADER
        // Given the following JSON header, encode it and 
        // assert it with the encoded header created by jjwt.
        String header = "{\"alg\":\"RS256\"}";
        String actualEncodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes());
        assertEquals(tokens[0], actualEncodedHeader);

        // JWT PAYLOAD
        // Given the following JSON payload, encode it and 
        // assert it with the encoded payload created by jjwt.
        String payload = "{\"sub\":\"adam\",\"exp\":61475608800,\"iss\":\"info@wstutorial.com\",\"groups\":[\"user\",\"admin\"]}";
        String actualEncodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes());
        assertEquals(tokens[1], actualEncodedPayload);

        // JWT SIGNATURE
        // For RSA, which is an asymmetic algorithm, two keys
        // are used, a public and a private key. The private
        // key is used to create the signature for the JWT.
        // The private key is only available to the Authentication
        // Server so that only the Authentication Server can
        // create new JWTs. The public key may be distributed
        // to Clients so that Clients can verify JWTs without
        // the need to make an authentication request (HTTPS)
        // to the Authentication Server. It is safe to give Clients
        // the public key because it can only be used to verify
        // a signature, it cannot be used to create a signature 
        // and subsequently new JWTs.
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update((actualEncodedHeader + "." + actualEncodedPayload).getBytes());
        String actualEncryptedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(
                privateSignature.sign()
        );
        assertEquals(tokens[2], actualEncryptedSignature);

        // CLIENT VERIFY
        // For RSA, which is an asymmetic algorithm, two keys
        // are used, a public and a private key. The public key
        // is used to verify the signature of the JWT. The 
        // Authentication Server will have the public key so
        // The Authentication Server can verify JWTs. A Client
        // would makea n authentication request (HTTPS) to the
        // Authentication Server to verify a JWT. However, A 
        // Client may alternatively be given a copy of the 
        // public key. It is safe to give Clients the public key 
        // because it can only be used to verify a signature, 
        // it cannot be used to create a signature and subsequently 
        // new JWTs. 
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update((actualEncodedHeader + "." + actualEncodedPayload).getBytes());
        boolean verified = publicSignature.verify(
            Base64.getUrlDecoder().decode(actualEncryptedSignature)
        );
        assertTrue(verified);
    }
}
