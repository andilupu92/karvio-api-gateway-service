package karvio.security;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtSecurityContextRepository implements ServerSecurityContextRepository {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtAuthenticationManager authenticationManager;

    public JwtSecurityContextRepository(JwtAuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        // Stateless — we don't save anything (no session)
        return Mono.empty();
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(AUTHORIZATION_HEADER);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return Mono.empty(); // No token → unauthenticated (Security decides what to do next)
        }

        String token = authHeader.substring(BEARER_PREFIX.length());

        // Build a pre-auth token and let the manager validate it
        Authentication preAuth = new UsernamePasswordAuthenticationToken(token, token);
        Mono<SecurityContext> contextMono = authenticationManager.authenticate(preAuth)
                .map(SecurityContextImpl::new);

        return contextMono.onErrorResume(BadCredentialsException.class, e -> Mono.empty());
    }
}
