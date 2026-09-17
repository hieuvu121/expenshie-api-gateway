package com.be9expensphie.gateway.listener;
import com.be9expensphie.gateway.filter.JwtAuthenticationFilter;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.ReactiveRedisMessageListenerContainer;
import org.springframework.stereotype.Component;
import reactor.core.Disposable;
import reactor.util.retry.Retry;

import java.time.Duration;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtRevocationListener {
    static final String JWT_REVOKED_CHANNEL = "jwt-revoked";

    private final ReactiveRedisMessageListenerContainer container;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    private Disposable subscription;


    //subscribe to listen once when app start
    @PostConstruct
    void subscribe(){
        this.subscription = container.receive(ChannelTopic.of(JWT_REVOKED_CHANNEL))
                .doOnNext(message -> jwtAuthenticationFilter.invalidate(message.getMessage()))//take out the message (jwt token) then call invalidate to evict
                .doOnError(e -> log.warn("jwt-revoked subscription dropped; retrying", e))
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1))
                        .maxBackoff(Duration.ofSeconds(30)))
                .subscribe();
        log.info("Subscribed to {}", JWT_REVOKED_CHANNEL);
    }

    @PreDestroy
    void unsubscribe(){
        if(subscription != null && !subscription.isDisposed()){
            subscription.dispose();
        }
    }

}
