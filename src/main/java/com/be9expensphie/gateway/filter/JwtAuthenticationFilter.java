package com.be9expensphie.gateway.filter;
import com.be9expensphie.gateway.util.JwtUtil;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {
    private final JwtUtil jwtUtil;
    private final ReactiveRedisTemplate<String,String> reactiveRedisTemplate;

    @Value("${app.jwt.blacklist-cache-ttl-seconds:10}")
    private long blacklistCacheTtlSeconds;

    @Value("${app.jwt.blacklist-cache-max-size:20000}")
    private long blacklistCacheMaxSize;

    private Cache<String, Boolean> blacklistCache;

    @PostConstruct
    void initCache() {
        this.blacklistCache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofSeconds(Math.max(blacklistCacheTtlSeconds, 0)))
                .maximumSize(blacklistCacheMaxSize)
                .build();
    }

    private static final List<String> PUBLIC_PATHS = List.of(
            "/app/v1/auth/login",
            "/app/v1/auth/register",
            "/app/v1/activate",
            "/app/v1/auth/forgot-password",
            "/app/v1/auth/reset-password"
    );

    /*
     * Indexed loop rather than a stream: this runs on every request, including
     * authenticated ones, and a stream pipeline plus a capturing lambda is a
     * per-request allocation to compare five constant prefixes.
     */
    private boolean isPublicPath(String path) {
        for (int i = 0; i < PUBLIC_PATHS.size(); i++) {
            if (path.startsWith(PUBLIC_PATHS.get(i))) {
                return true;
            }
        }
        return false;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if(isPublicPath(path)){
            return chain.filter(exchange);
        }

        String authHeader=exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if(authHeader==null||!authHeader.startsWith("Bearer ")){
            return unauthorized(exchange);
        }

        String token=authHeader.substring(7);

        // One parse per request. Previously isTokenValid/extractUserId/extractEmail
        // each parsed and HMAC-verified the token separately — three times over.
        Claims claims = jwtUtil.parseIfValid(token);
        if (claims == null) {
            return unauthorized(exchange);
        }

        Boolean cached = blacklistCache.getIfPresent(token);
        if (cached != null) {
            return Boolean.TRUE.equals(cached) ? unauthorized(exchange) : forward(exchange, chain, claims);
        }

        return reactiveRedisTemplate.hasKey("blacklist:" + token)
                .defaultIfEmpty(Boolean.FALSE)
                .flatMap(isBlacklisted -> {
                    blacklistCache.put(token, Boolean.TRUE.equals(isBlacklisted));
                    return Boolean.TRUE.equals(isBlacklisted)
                            ? unauthorized(exchange)
                            : forward(exchange, chain, claims);
                });
    }

    private Mono<Void> forward(ServerWebExchange exchange, GatewayFilterChain chain, Claims claims) {
        Long userId = claims.get("userId", Long.class);
        String email = claims.getSubject();

        ServerHttpRequest mutated = exchange.getRequest().mutate()
                .header("X-User-Id", userId != null ? userId.toString() : "")
                .header("X-User-Email", email != null ? email : "")
                .build();
        return chain.filter(exchange.mutate().request(mutated).build());
    }

    @Override
    public int getOrder() {
        return -1;
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }

    public void invalidate(String token){
        blacklistCache.invalidate(token);
    }
}
