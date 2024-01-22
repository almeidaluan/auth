package br.com.microservice.statelessauthapi.service;


import br.com.microservice.statelessauthapi.core.model.User;
import br.com.microservice.statelessauthapi.infra.exception.AuthenticationException;
import br.com.microservice.statelessauthapi.infra.exception.ValidationException;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;

@Service
@RequiredArgsConstructor
public class JwtService {

    @Value("${app.token.secret-key}")
    private String secretKey;

    private static final int ONE_DAY_HOURS = 24;

    private static final String empty_space = " ";

    private static final int token_index = 1;


    public String CreateToken(User user) {

        var data = new HashMap<String, String>();
        data.put("id", user.getId().toString());
        data.put("username", user.getUsername());
        return Jwts
                .builder()
                .claims(data)
                .expiration(ExpirationToken())
                .signWith(genereteSign())
                .compact();
    }

    public void ValidateAccessToken(String token) {
        var accessToken = extractToken(token);

        try {
            Jwts.parser().verifyWith(genereteSign()).build().parseSignedClaims(accessToken).getPayload();

        } catch (Exception ex) {
            throw new AuthenticationException("Invalid token " + ex.getMessage());
        }
    }

    private Date ExpirationToken() {
        return Date.from(
                LocalDateTime.now().plusHours(ONE_DAY_HOURS)
                        .atZone(ZoneId.systemDefault()).toInstant()
        );
    }

    private SecretKey genereteSign() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    private String extractToken(String token) {
        if (token.isEmpty()) {
            throw new ValidationException("The access token was not informed");
        }
        if (token.contains(empty_space)) {
            return token.split(empty_space)[token_index]; // pegando os tokens no formato Bearer token
        }
        return token;
    }
}
