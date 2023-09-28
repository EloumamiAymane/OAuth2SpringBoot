package com.jwt.Authentication.auth.Services;

import com.jwt.Authentication.auth.DTO.LoginRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class TokenService {
    private JwtEncoder jwtEncoder;

    public TokenService(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    public Map<String,String>generateToken(String username,
                                       Collection<? extends GrantedAuthority> authorities,
                                       boolean withRefreshToken){
    //create map which will contains token
    Map<String,String > idToken=new HashMap<>();

    //convert authorithies to String
    String scope=authorities.stream()
        .map(auth->auth.getAuthority())
        .collect(Collectors.joining(" "));
    //creer l'objet instant qui a l'heure courrante
    Instant instant = Instant.now();
    //creer les claims
    JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
            .subject(username)
            .issuedAt(instant)
            .expiresAt(instant.plus(withRefreshToken ? 1 : 1, ChronoUnit.MINUTES))
            .issuer("securityservice")
            .claim("scope", scope)
            .build();

    //generate Token
    String jwtAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet))
            .getTokenValue();
    //stock access token in the map
    idToken.put("accessToken",jwtAccessToken);

    //si on veut le refresh token aussi
    if(withRefreshToken)
    {
        JwtClaimsSet jwtClaimsSetRefresh = JwtClaimsSet.builder()
                .subject(username)
                .issuedAt(instant)
                .expiresAt(instant.plus(2,ChronoUnit.MINUTES))
                .issuer("securityservice")
                .build();
        String jwtRefreshoken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh))
                .getTokenValue();
        idToken.put("refreshToken", jwtRefreshoken);

    }
    return idToken;
}

}
