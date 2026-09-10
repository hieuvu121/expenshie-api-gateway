package com.be9expensphie.gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
public class JwtUtil {

    @Value("${app.jwt.secret}")
    private String secret;

    /**
     * Parser and key are both built once and reused.
     *
     * The filter used to parse the token three times per request (validate,
     * extract id, extract email), each parse re-encoding the secret and
     * rebuilding the key. Memoizing the key fixed most of that, but every
     * request still ran Jwts.parser()...build(), which constructs a
     * DefaultJwtParser and resolves a Deserializer through a service lookup.
     * JwtParser is thread-safe and meant to be built once, so it is cached the
     * same way the key is.
     */
    private volatile JwtParser parser;

    private JwtParser parser() {
        JwtParser p = parser;
        if (p == null) {
            synchronized (this) {
                if (parser == null) {
                    SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
                    parser = Jwts.parser().verifyWith(key).build();
                }
                p = parser;
            }
        }
        return p;
    }

    /**
     * Verify signature and expiry in a single parse, returning the claims so the
     * caller can read them without parsing again. Null when invalid or expired.
     *
     * parseSignedClaims already validates exp and throws ExpiredJwtException,
     * so there is no second expiry check here - the previous one re-read the
     * claim and allocated a Date per request to re-answer a question the parser
     * had already answered.
     */
    public Claims parseIfValid(String token) {
        try {
            return parser().parseSignedClaims(token).getPayload();
        } catch (Exception e) {
            return null;
        }
    }
}
