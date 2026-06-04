package karvio.security;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class UserHeadersFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;

    public UserHeadersFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return exchange.getPrincipal()
                .cast(UsernamePasswordAuthenticationToken.class)
                .flatMap(authentication -> {
                    // Credentials hold the raw JWT token (set in JwtAuthenticationManager)
                    String token = authentication.getCredentials().toString();
                    DecodedJWT decoded = jwtUtil.validateAndExtractClaims(token);

                    String userId = jwtUtil.extractUserId(decoded);
                    String username = authentication.getName(); // = subject from token
                    String roles = String.join(",", jwtUtil.extractRoles(decoded));
                    // Mutate the request — add custom headers for downstream services
                    ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                            .header("X-User-Id", userId)
                            .header("X-User-Name", username)
                            .header("X-User-Roles", roles)
                            // remove raw JWT so downstream services don't re-validate
                            // .headers(headers -> headers.remove(AUTHORIZATION_HEADER))
                            .build();
                    return chain.filter(exchange.mutate().request(mutatedRequest).build());
                })
                // If no principal (unauthenticated/public route), just continue normally
                .switchIfEmpty(chain.filter(exchange));
    }

    @Override
    public int getOrder() {
        // Must run AFTER Spring Security (-1) but before routing (Integer.MIN_VALUE is highest)
        return 1;
    }
}