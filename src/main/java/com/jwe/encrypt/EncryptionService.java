package com.jwe.encrypt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

import org.json.JSONObject;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;



public class EncryptionService {

    private Request request=new Request();

    public void encryptTrail(){


        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");

            keyPairGenerator.initialize(2048);

            // generate the key pair
            KeyPair keyPair = keyPairGenerator.genKeyPair();

            // create KeyFactory and RSA Keys Specs
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
            RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);

            // generate (and retrieve) RSA Keys from the KeyFactory using Keys Specs
            RSAPublicKey publicRsaKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
            RSAPrivateKey privateRsaKey  = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

            System.out.println("---------------------PUBLIC KEY-------------------------------");
            System.out.println(publicRsaKey);
            System.out.println("----------------------------------------------------");


            JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();
            claimsSet.issuer("https://my-auth-server.com");
            claimsSet.subject("John Kerr");
            claimsSet.audience(getAudience());
            claimsSet.expirationTime(new Date(new Date().getTime() + 1000*60*10));
            claimsSet.notBeforeTime(new Date());
            claimsSet.jwtID(UUID.randomUUID().toString());

            System.out.println("--------------------------");
            System.out.println("Claim Set : \n"+claimsSet.build());


            org.json.JSONObject paloadJson=new JSONObject();
            paloadJson.accumulate("fname","chandan");
            paloadJson.accumulate("lname","bala");


            Payload payload=new Payload(paloadJson.toString());

            // create the JWT header and specify:
            //  RSA-OAEP as the encryption algorithm
            //  128-bit AES/GCM as the encryption method
            JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);
            JWEObject jwt = new JWEObject(header, payload);
            // create the EncryptedJWT object
            //EncryptedJWT jwt = new EncryptedJWT(header, claimsSet.build());

            // create an RSA encrypter with the specified public RSA key
            RSAEncrypter encrypter = new RSAEncrypter(publicRsaKey);

            // do the actual encryption
            jwt.encrypt(encrypter);

            // serialize to JWT compact form
            String jwtString = jwt.serialize();
            System.out.println("\nJwt Compact Form : "+jwtString);

            // in order to read back the data from the token using your private RSA key:
            // parse the JWT text string using EncryptedJWT object
            jwt = EncryptedJWT.parse(jwtString);

            // create a decrypter with the specified private RSA key
            RSADecrypter decrypter = new RSADecrypter(privateRsaKey);

            // do the decryption
            jwt.decrypt(decrypter);

            // print out the claims

            System.out.println("===========================================================");
           // System.out.println("Issuer: [ " + jwt.getJWTClaimsSet().getIssuer() + "]");
           // System.out.println("Subject: [" + jwt.getJWTClaimsSet().getSubject()+ "]");
           // System.out.println("Audience size: [" + jwt.getJWTClaimsSet().getAudience().size()+ "]");
           //// System.out.println("Expiration Time: [" + jwt.getJWTClaimsSet().getExpirationTime()+ "]");
            //System.out.println("Not Before Time: [" + jwt.getJWTClaimsSet().getNotBeforeTime()+ "]");
           // System.out.println("Issue At: [" + jwt.getJWTClaimsSet().getIssueTime()+ "]");
            //System.out.println("JWT ID: [" + jwt.getJWTClaimsSet().getJWTID()+ "]");
            System.out.println("content: [ " + ((EncryptedJWT) jwt).getJWTClaimsSet() + "]");
            System.out.println("header: [ " + jwt.getHeader()+ "]");
            System.out.println("enc key: [ " + jwt.getEncryptedKey()+ "]");
            System.out.println("integrated vector: [ " + jwt.getIV()+ "]");
            System.out.println("chiper text: [ " + jwt.getCipherText()+ "]");
            System.out.println("auth tag: [ " + jwt.getAuthTag() + "]");


            System.out.println("===========================================================");

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static List<String> getAudience(){
        List<String> audience = new ArrayList<String>();
        audience.add("https://my-web-app.com");
        audience.add("https://your-web-app.com");
        return audience;
    }

}
