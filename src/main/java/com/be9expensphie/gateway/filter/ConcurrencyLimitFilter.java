package com.be9expensphie.gateway.filter;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Admission control: caps how many requests may be in flight through this
 * gateway instance at once, and sheds the rest with 429.
 *
 * The gateway buffers each in-flight request on the heap with no natural
 * bound. Measured at 4000 RPS: heap 264 MiB to 1482 MiB, GC taking 16% of
 * wall time, gateway p95 0.61s to 5.32s while the services behind it moved
 * only 0.13s to 0.27s, ending in an OOM kill (exit 137). Throughput *fell*
 * from 2923 to 1814 req/s under the extra load. Rejecting early converts that
 * collapse into flat throughput plus refusals.
 *
 * Runs before JwtAuthenticationFilter (order -1) on purpose: a rejected
 * request must not pay for an HMAC verification first. Shedding has to be
 * cheaper than serving, or it makes overload worse.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ConcurrencyLimitFilter implements GlobalFilter, Ordered {

    private final MeterRegistry meterRegistry;

    /** Max concurrent in-flight requests. 0 disables the limiter entirely. */
    @Value("${app.gateway.max-in-flight:500}")
    private int maxInFlight;

    private final AtomicInteger inFlight = new AtomicInteger();
    private Counter rejected;

    @PostConstruct
    void initMetrics() {
        Gauge.builder("gateway.inflight.requests", inFlight, AtomicInteger::get)
                .description("Requests currently in flight through this gateway instance")
                .register(meterRegistry);
        this.rejected = Counter.builder("gateway.requests.rejected")
                .description("Requests shed by the concurrency limiter")
                .register(meterRegistry);
        log.info("Gateway concurrency limit: {}", maxInFlight > 0 ? String.valueOf(maxInFlight) : "disabled");
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (maxInFlight <= 0) {
            return chain.filter(exchange);
        }

        /*
         * Increment first, then check. Check-then-increment races: two threads
         * both read limit-1 and both proceed, so the cap leaks under exactly
         * the load it exists to handle.
         */
        if (inFlight.incrementAndGet() > maxInFlight) {
            inFlight.decrementAndGet();
            rejected.increment();
            return tooManyRequests(exchange);
        }

        /*
         * doFinally fires exactly once for any terminal signal - onComplete,
         * onError and cancel. Cancel matters most here: a client giving up
         * mid-request is precisely what happens during overload, and
         * decrementing only on success would leak the counter up to the cap
         * and wedge the gateway shut permanently.
         */
        return chain.filter(exchange)
                .doFinally(signal -> inFlight.decrementAndGet());
    }

    private Mono<Void> tooManyRequests(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        response.getHeaders().add(HttpHeaders.RETRY_AFTER, "1");
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        // Below JwtAuthenticationFilter's -1, so admission is decided first.
        return -100;
    }
}
