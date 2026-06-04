package karvio.fallback;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@RestController
public class AuthFallbackController {

    private static final Logger log = LoggerFactory.getLogger(AuthFallbackController.class);

    private final Counter fallbackCounter;
    private final Timer fallbackTimer;

    public AuthFallbackController(MeterRegistry registry) {
        this.fallbackCounter = Counter.builder("gateway.fallback.count")
                .description("Number of fallback responses returned by gateway")
                .tag("service", "karvio-auth-service")
                .register(registry);

        this.fallbackTimer = Timer.builder("gateway.fallback.latency")
                .description("Latency of fallback handler")
                .tag("service", "karvio-auth-service")
                .publishPercentiles(0.5, 0.95)
                .register(registry);
    }

    @RequestMapping("/fallback/karvio-auth-service-fallback")
    public Mono<ResponseEntity<Map<String, Object>>> handleFallback(ServerWebExchange exchange) {
        String requestId = exchange.getRequest().getHeaders().getFirst("X-Request-Id");

        if (requestId == null || requestId.isBlank()) {
            requestId = UUID.randomUUID().toString();
        }

        long start = System.nanoTime();
        fallbackCounter.increment();

        MDC.put("requestId", requestId);
        try {
            log.warn("Fallback triggered for route karvio-auth-service; path={} method={}",
                    exchange.getRequest().getPath(), exchange.getRequest().getMethod());

            Map<String, Object> body = Map.of(
                    "code", "SERVICE_UNAVAILABLE",
                    "message", "The authentication service is temporarily unavailable. Please try again later.",
                    "service", "karvio-auth-service",
                    "timestamp", Instant.now().toString(),
                    "requestId", requestId
            );

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.add("X-Request-Id", requestId);
            headers.add("Retry-After", "30");

            long elapsed = System.nanoTime() - start;
            fallbackTimer.record(elapsed, TimeUnit.NANOSECONDS);

            return Mono.just(ResponseEntity
                    .status(HttpStatus.SERVICE_UNAVAILABLE)
                    .headers(headers)
                    .body(body));

        } finally {
            MDC.remove("requestId");
        }
    }
}