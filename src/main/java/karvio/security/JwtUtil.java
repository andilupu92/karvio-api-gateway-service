package karvio.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    private Algorithm getAlgorithm() {
        return Algorithm.HMAC256(secret);
    }

    private JWTVerifier getVerifier() {
        return JWT.require(getAlgorithm())
                .build();
    }

    // ✅ Verifies signature + expiration in one call
    public DecodedJWT validateAndExtractClaims(String token) {
        // Throws TokenExpiredException if expired
        // Throws SignatureVerificationException if signature is invalid
        // Throws JWTVerificationException for any other issue
        return getVerifier().verify(token);
    }

    public String extractUserId(DecodedJWT decodedJWT) {
        Claim userIdClaim = decodedJWT.getClaim("userId");
        return String.valueOf(userIdClaim.asLong());
    }

    public List<String> extractRoles(DecodedJWT decodedJWT) {
        Claim rolesClaim = decodedJWT.getClaim("role");
        if (rolesClaim.isNull()) {
            return List.of();
        }
        return rolesClaim.asList(String.class);
    }
}