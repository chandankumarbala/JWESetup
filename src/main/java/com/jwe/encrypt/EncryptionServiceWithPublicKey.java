package com.jwe.encrypt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.json.JSONObject;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Enumeration;


public class EncryptionServiceWithPublicKey {


    public byte[] getKey(String key) {
        try {

            StringBuilder pkcs8Lines = new StringBuilder();
            BufferedReader rdr = new BufferedReader(new StringReader(key));
            String line;
            while ((line = rdr.readLine()) != null) {
                pkcs8Lines.append(line);
            }

            // Remove the "BEGIN" and "END" lines, as well as any whitespace

            String pkcs8Pem = pkcs8Lines.toString();
            pkcs8Pem = pkcs8Pem.replace("-----BEGIN RSA PRIVATE KEY-----", "");
            pkcs8Pem = pkcs8Pem.replace("-----END RSA PRIVATE KEY-----", "");
            pkcs8Pem = pkcs8Pem.replace("-----BEGIN CERTIFICATE-----", "");
            pkcs8Pem = pkcs8Pem.replace("-----END CERTIFICATE-----", "");
            pkcs8Pem = pkcs8Pem.replaceAll("\\s+", "");


            return Base64.decodeBase64(pkcs8Pem);//key.getBytes();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }


    public PublicKey getKeyPublicKey(String key) {
        System.out.println("---------------------PUBLIC KEY-------------------------------" + key);

        try {
            byte[] byteKey = this.getKey(key);
            InputStream certstream = new ByteArrayInputStream(byteKey);
            Certificate cert = CertificateFactory.getInstance("X.509").generateCertificate(certstream);


            //X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
            //KeyFactory kf = KeyFactory.getInstance("RSA");

            return cert.getPublicKey();//kf.generatePublic(X509publicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }


    public PrivateKey getKeyPrivateey(String key) {

        System.out.println("---------------------PRIVATE KEY-------------------------------" + key);


        String privKeyPEM = key.replace(
                "-----BEGIN RSA PRIVATE KEY-----\n", "")
                .replace("-----END RSA PRIVATE KEY-----", "");

        byte[] encodedPrivateKey = Base64.decodeBase64(privKeyPEM);

        try {
            ASN1Sequence primitive = (ASN1Sequence) ASN1Sequence
                    .fromByteArray(encodedPrivateKey);
            Enumeration<?> e = primitive.getObjects();
            BigInteger v = ((DERInteger) e.nextElement()).getValue();

            int version = v.intValue();
            if (version != 0 && version != 1) {
                throw new IllegalArgumentException("wrong version for RSA private key");
            }
            /**
             * In fact only modulus and private exponent are in use.
             */
            BigInteger modulus = ((DERInteger) e.nextElement()).getValue();
            BigInteger publicExponent = ((DERInteger) e.nextElement()).getValue();
            BigInteger privateExponent = ((DERInteger) e.nextElement()).getValue();
            BigInteger prime1 = ((DERInteger) e.nextElement()).getValue();
            BigInteger prime2 = ((DERInteger) e.nextElement()).getValue();
            BigInteger exponent1 = ((DERInteger) e.nextElement()).getValue();
            BigInteger exponent2 = ((DERInteger) e.nextElement()).getValue();
            BigInteger coefficient = ((DERInteger) e.nextElement()).getValue();

            RSAPrivateKeySpec spec = new RSAPrivateKeySpec(modulus, privateExponent);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey pk = kf.generatePrivate(spec);
            return pk;
        } catch (IOException e2) {
            throw new IllegalStateException();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }

    }

    public void encryptTrail() {
        Request request = new Request();

        KeyPairGenerator keyPairGenerator;
        try {


            // keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            //keyPairGenerator.initialize(2048);


            // generate the key pair
            // KeyPair keyPair = keyPairGenerator.genKeyPair();
            PublicKey partnerPublicKey = this.getKeyPublicKey(request.getPublickey());
            PrivateKey partnerPrivatekey = this.getKeyPrivateey(request.getPrivateKey());

            // create KeyFactory and RSA Keys Specs
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(partnerPublicKey, RSAPublicKeySpec.class);
            RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(partnerPrivatekey, RSAPrivateKeySpec.class);

            // generate (and retrieve) RSA Keys from the KeyFactory using Keys Specs
            RSAPublicKey publicRsaKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
            RSAPrivateKey privateRsaKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

            System.out.println("---------------------PRIVATE KEY-------------------------------");

            JSONObject paloadJson = new JSONObject();
            paloadJson.accumulate("fname", "chandan");
            paloadJson.accumulate("lname", "bala");


            Payload payload = new Payload(paloadJson.toString());

            // create the JWT header and specify:
            //  RSA-OAEP as the encryption algorithm
            //  128-bit AES/GCM as the encryption method
            JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);
            JWEObject jwt = new JWEObject(header, payload);

            // create an RSA encrypter with the specified public RSA key
            RSAEncrypter encrypter = new RSAEncrypter(publicRsaKey);
            // do the actual encryption
            jwt.encrypt(encrypter);
            // serialize to JWT compact form
            String jwtString = jwt.serialize();
            System.out.println("\nJwt Compact Form : " + jwtString);

            // in order to read back the data from the token using your private RSA key:
            // parse the JWT text string using EncryptedJWT object
            jwt = EncryptedJWT.parse(jwtString);

            // create a decrypter with the specified private RSA key
            RSADecrypter decrypter = new RSADecrypter(privateRsaKey);

            // do the decryption
            jwt.decrypt(decrypter);

            // print out the claims

            System.out.println("===========================================================");
            System.out.println("content: [ " + ((EncryptedJWT) jwt).getJWTClaimsSet() + "]");
            System.out.println("header: [ " + jwt.getHeader() + "]");
            System.out.println("enc key: [ " + jwt.getEncryptedKey() + "]");
            System.out.println("integrated vector: [ " + jwt.getIV() + "]");
            System.out.println("chiper text: [ " + jwt.getCipherText() + "]");
            System.out.println("auth tag: [ " + jwt.getAuthTag() + "]");
            System.out.println("===========================================================");

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }


}
