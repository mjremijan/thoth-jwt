/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Project/Maven2/JavaApp/src/main/java/${packagePath}/${mainClassName}.java to edit this template
 */
package org.thoth.jwt;

import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Date;

/**
 *
 * @author mjrem
 */
public class ThothJwt {

    public static void main(String[] args) throws Exception {
        new ThothJwt().main();
    }

    public void main() throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);

        KeyPair kp = keyGenerator.genKeyPair();
        PublicKey publicKey = (PublicKey) kp.getPublic();
        PrivateKey privateKey = (PrivateKey) kp.getPrivate();

        String encodedPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        System.out.println("Public Key:");
        System.out.println(convertToPublicKey(encodedPublicKey));
        String token = generateJwtToken(privateKey);
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
        printStructure(token, publicKey);
        
        
        // MINE
        System.out.printf("%nMINE:%n");
        // HEADER
        {
            String headerFromExampleEncoded = "eyJhbGciOiJSUzI1NiJ9";
            String headerFromExampleDecoded = new String(Base64.getUrlDecoder().decode(headerFromExampleEncoded));
            System.out.printf("%-30s: %s%n", "headerFromExampleDecoded", headerFromExampleDecoded);
        }
        {
            String headerFromExampleDecoded = "{\"alg\":\"RS256\"}";
            // 1
            String myHeaderEncoding1 = Base64.getUrlEncoder().encodeToString(headerFromExampleDecoded.getBytes());
            System.out.printf("%-30s: %s  %b%n", "myHeaderEncoding1", myHeaderEncoding1, jwtHeader.equals(myHeaderEncoding1));
            // 2
            String myHeaderEncoding2 = URLEncoder.encode(Base64.getEncoder().encodeToString(headerFromExampleDecoded.getBytes()), "utf-8");
            System.out.printf("%-30s: %s  %b%n", "myHeaderEncoding2", myHeaderEncoding2, jwtHeader.equals(myHeaderEncoding2));
        }
        // PAYLOAD
                {
            String payloadFromExampleEncoded = "eyJzdWIiOiJhZGFtIiwiZXhwIjo2MTQ3NTYwODgwMCwiaXNzIjoiaW5mb0B3c3R1dG9yaWFsLmNvbSIsImdyb3VwcyI6WyJ1c2VyIiwiYWRtaW4iXX0";
            String payloadFromExampleDecoded = new String(Base64.getUrlDecoder().decode(payloadFromExampleEncoded));
            System.out.printf("%-30s: %s%n", "payloadFromExampleDecoded", payloadFromExampleDecoded);
        }
        {
            String payloadFromExampleDecoded = "{\"sub\":\"adam\",\"exp\":61475608800,\"iss\":\"info@wstutorial.com\",\"groups\":[\"user\",\"admin\"]}";
            // 1
            String myPayloadEncoding1 = Base64.getUrlEncoder().encodeToString(payloadFromExampleDecoded.getBytes());
            System.out.printf("%-30s: %s  %b%n", "myPayloadEncoding1", myPayloadEncoding1, jwtPayload.equals(myPayloadEncoding1));
            // 2
            String myPayloadEncoding2 = URLEncoder.encode(Base64.getEncoder().encodeToString(payloadFromExampleDecoded.getBytes()), "utf-8");
            System.out.printf("%-30s: %s  %b%n", "myPayloadEncoding2", myPayloadEncoding2, jwtPayload.equals(myPayloadEncoding2));
            // 3
            String myPayloadEncoding3 = URLEncoder.encode(Base64.getEncoder().withoutPadding().encodeToString(payloadFromExampleDecoded.getBytes()), "utf-8");
            System.out.printf("%-30s: %s  %b%n", "myPayloadEncoding3", myPayloadEncoding3, jwtPayload.equals(myPayloadEncoding3));
            
            // actual
            System.out.printf("%-30s: %s%n", "jwtPayload", jwtPayload);
        }
        
        
        
        
    }

    public String generateJwtToken(PrivateKey privateKey) {
        String token = 
                Jwts.builder().setSubject("adam")
                .setExpiration(new Date(2018, 1, 1))
                .setIssuer("info@wstutorial.com")
                .claim("groups", new String[]{"user", "admin"})
                // RS256 with privateKey
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
        return token;
    }

    //Print structure of JWT
    public void printStructure(String token, PublicKey publicKey) {
        Jws parseClaimsJws = Jwts.parser().setSigningKey(publicKey)
                .parseClaimsJws(token);

        System.out.println("Header     : " + parseClaimsJws.getHeader());
        System.out.println("Body       : " + parseClaimsJws.getBody());
        System.out.println("Signature  : " + parseClaimsJws.getSignature());
    }

    // Add BEGIN and END comments
    private String convertToPublicKey(String key) {
        StringBuilder result = new StringBuilder();
        result.append("-----BEGIN PUBLIC KEY-----\n");
        result.append(key);
        result.append("\n-----END PUBLIC KEY-----");
        return result.toString();
    }
    
    /*
    protected byte[] doSign(byte[] data) throws InvalidKeyException, java.security.SignatureException {
        PrivateKey privateKey = (PrivateKey)key;
        Signature sig = createSignatureInstance();
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }
    
    
    protected Signature createSignatureInstance() {

        Signature sig = super.createSignatureInstance();

        PSSParameterSpec spec = PSS_PARAMETER_SPECS.get(alg); // this returns null
        if (spec != null) {
            setParameter(sig, spec);
        }
        return sig;
    }

    protected void setParameter(Signature sig, PSSParameterSpec spec) {
        try {
            doSetParameter(sig, spec);
        } catch (InvalidAlgorithmParameterException e) {
            String msg = "Unsupported RSASSA-PSS parameter '" + spec + "': " + e.getMessage();
            throw new SignatureException(msg, e);
        }
    }

    protected void doSetParameter(Signature sig, PSSParameterSpec spec) throws InvalidAlgorithmParameterException {
        sig.setParameter(spec);
    }
    
    protected Signature createSignatureInstance() {
        try {
            return getSignatureInstance();
        } catch (NoSuchAlgorithmException e) {
            String msg = "Unavailable " + alg.getFamilyName() + " Signature algorithm '" + alg.getJcaName() + "'.";
            if (!alg.isJdkStandard() && !isBouncyCastleAvailable()) {
                msg += " This is not a standard JDK algorithm. Try including BouncyCastle in the runtime classpath.";
            }
            throw new SignatureException(msg, e);
        }
    }

    protected Signature getSignatureInstance() throws NoSuchAlgorithmException {
        return Signature.getInstance(alg.getJcaName());  // "RS256"
    }
    */
}
