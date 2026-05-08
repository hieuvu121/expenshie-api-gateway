package com.be9expensphie.gateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfig {

    @Bean
    public RouteLocator routes(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("auth-service",    r -> r.path("/app/v1/auth/**", "/app/v1/users/**", "/app/v1/activate")
                        .uri("lb://auth-service"))
                // expense-service must be before household-service — it handles /households/*/expenses/**
                .route("expense-service", r -> r.path("/app/v1/households/*/expenses/**", "/app/v1/households/*/expenses")
                        .uri("lb://expense-service"))
                .route("household-service", r -> r.path("/app/v1/households/**")
                        .uri("lb://household-service"))
                .route("settlement-service", r -> r.path("/app/v1/settlements/**")
                        .uri("lb://settlement-service"))
                .route("notification-ws",  r -> r.path("/ws/**")
                        .uri("lb:ws://notification-service"))
                .build();
    }
}