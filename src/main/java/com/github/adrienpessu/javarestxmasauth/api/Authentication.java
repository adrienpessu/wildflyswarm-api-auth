package com.github.adrienpessu.javarestxmasauth.api;


import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.google.common.base.Strings;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import java.io.IOException;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by adrien on 04/02/2017.
 */
@Path("/auth")
public class Authentication {


    @POST
    @Produces("application/json")
    @Consumes("application/json")
    @Path("/get")
    public String get(String user) throws JoseException, IOException, InvalidJwtException {
        final String jwtSecret = getSecret();
        final Map<String, String> parameters = getParameters(user);

        String jwt = "";

        if(("admin".equals(parameters.get("password"))
            || "invite".equals(parameters.get("password")))) {

            if(!parameters.containsKey("name")){
                parameters.put("name", parameters.get("password"));
            }


            JwtClaims claims = new JwtClaims();
            claims.setExpirationTimeMinutesInTheFuture(3600);
            claims.setSubject("foki");
            claims.setIssuer("the issuer");
            claims.setAudience("the audience");
            claims.setClaim("payload", parameters.get("name"));

            Key key = new HmacKey(jwtSecret.getBytes("UTF-8"));

            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(claims.toJson());
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
            jws.setKey(key);
            jws.setDoKeyValidation(false); // relaxes the key length requirement

            jwt = jws.getCompactSerialization();

        }

        JSONObject resultat = new JSONObject();

        resultat.put("name", parameters.get("name"));
        resultat.put("token", jwt);
        return resultat.toJSONString();
    }

    @POST
    @Produces("application/json")
    @Consumes("application/json")
    @Path("/check")
    public String check(String user) throws JoseException, IOException, InvalidJwtException {

        final String jwtSecret = getSecret();
        final Map<String, String> parameters = getParameters(user);

        Key key = new HmacKey(jwtSecret.getBytes("UTF-8"));

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(30)
                .setRequireSubject()
                .setExpectedIssuer("the issuer")
                .setExpectedAudience("the audience")
                .setVerificationKey(key)
                .setRelaxVerificationKeyValidation() // relaxes key length requirement
                .build();

        JwtClaims processedClaims = jwtConsumer.processToClaims(parameters.get("token"));
        JSONObject resultat = new JSONObject();

        resultat.put("name", processedClaims.getClaimValue("payload"));
        resultat.put("checked", true);
        return resultat.toJSONString();
    }


    private Map<String, String> getParameters(String user) throws IOException {
        JsonFactory factory = new JsonFactory();
        JsonParser parser  = factory.createParser(user);
        Map<String, String> parameters = new HashMap();
        while(!parser.isClosed()){
            JsonToken jsonToken = parser.nextToken();

            if(JsonToken.FIELD_NAME.equals(jsonToken)){
                String fieldName = parser.getCurrentName();
                parser.nextToken();

                parameters.put(fieldName, parser.getValueAsString());
            }
        }

        return parameters;
    }

    private String getSecret(){
        String jwtSecret = System.getenv("JWT_SECRET");
        if(Strings.isNullOrEmpty(jwtSecret)){
            jwtSecret = "password";
        }
        return jwtSecret;
    }
}
