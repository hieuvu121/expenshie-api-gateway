package com.be9expensphie.gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtil {

    @Value("${app.jwt.secret}")
    private String secret;

    /**
     * Derived once. This used to run per parse — and since the filter parsed the
     * token three times per request (validate, extract id, extract email), every
     * request re-encoded the secret to bytes and rebuilt the key three times.
     */
    private volatile SecretKey signingKey;

    private SecretKey getSigningKey() {
        SecretKey key = signingKey;
        if (key == null) {
            synchronized (this) {
                if (signingKey == null) {
                    signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
                }
                key = signingKey;
            }
        }
        return key;
    }

    /**
     * Verify signature and expiry in a single parse, returning the claims so the
     * caller can read them without parsing again. Null when invalid or expired.
     */
    public Claims parseIfValid(String token) {
        try {
            Claims claims = extractAllClaims(token);
            Date expiration = claims.getExpiration();
            return (expiration == null || expiration.before(new Date())) ? null : claims;
        } catch (Exception e) {
            return null;
        }
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        return claimsResolver.apply(extractAllClaims(token));
    }

    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Long extractUserId(String token) {
        return extractClaim(token, claims -> claims.get("userId", Long.class));
    }

    public boolean isTokenExpired(String token) {
        Date expiration = extractClaim(token, Claims::getExpiration);
        return expiration.before(new Date());
    }

    public boolean isTokenValid(String token) {
        try {
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }
}
