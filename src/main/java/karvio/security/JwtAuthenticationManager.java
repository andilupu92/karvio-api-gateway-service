package karvio.security;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtAuthenticationManager implements ReactiveAuthenticationManager {

    private final JwtUtil jwtUtil;

    public JwtAuthenticationManager(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String token = authentication.getCredentials().toString();

        return Mono.fromCallable(() -> jwtUtil.validateAndExtractClaims(token))
                .map(decodedJWT -> {
                    String username = decodedJWT.getSubject();
                    List<SimpleGrantedAuthority> authorities = jwtUtil.extractRoles(decodedJWT)
                            .stream()
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                            .toList();

                    return (Authentication) new UsernamePasswordAuthenticationToken(
                            username, token, authorities
                    );
                })
                .onErrorMap(TokenExpiredException.class,
                        e -> new BadCredentialsException("JWT token is expired", e))
                .onErrorMap(SignatureVerificationException.class,
                        e -> new BadCredentialsException("Invalid JWT signature", e))
                .onErrorMap(JWTVerificationException.class,
                        e -> new BadCredentialsException("JWT validation failed", e))
                .onErrorMap(JWTDecodeException.class,
                        e -> new BadCredentialsException("Malformed JWT token", e));
    }
}
