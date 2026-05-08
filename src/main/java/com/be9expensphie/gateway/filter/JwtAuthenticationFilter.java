package com.be9expensphie.gateway.filter;
import com.be9expensphie.gateway.util.JwtUtil;
import lombok.RequiredArgsConstructor;
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

import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {
    private final JwtUtil jwtUtil;
    private final ReactiveRedisTemplate<String,String> reactiveRedisTemplate;

    private static final List<String> PUBLIC_PATHS = List.of(
            "/app/v1/auth/login",
            "/app/v1/auth/register",
            "/app/v1/activate",
            "/app/v1/auth/forgot-password",
            "/app/v1/auth/reset-password"
    );

    private boolean isPublicPath(String path) {
        return PUBLIC_PATHS.stream().anyMatch(path::startsWith);
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

        if(!jwtUtil.isTokenValid(token)){
            return unauthorized(exchange);
        }

        return reactiveRedisTemplate.hasKey("blacklist:" +token)
                .flatMap(isBlacklisted->{
                    if(Boolean.TRUE.equals(isBlacklisted)){
                        return unauthorized(exchange);
                    }
                    Long userId= jwtUtil.extractUserId(token);
                    String email=jwtUtil.extractEmail(token);

                    ServerHttpRequest mutated=exchange.getRequest().mutate()
                            .header("X-User-Id",userId!=null? userId.toString():"")
                            .header("X-User-Email",email!=null?email.toString():"")
                            .build();
                    return chain.filter(exchange.mutate().request(mutated).build());
                });
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
}
