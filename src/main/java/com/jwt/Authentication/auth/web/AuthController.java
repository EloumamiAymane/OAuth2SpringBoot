package com.jwt.Authentication.auth.web;

import com.jwt.Authentication.auth.DTO.LoginRequest;
import com.jwt.Authentication.auth.Entity.AppUser;
import com.jwt.Authentication.auth.Services.AccountService;
import com.jwt.Authentication.auth.Services.TokenService;
import lombok.extern.log4j.Log4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.Map;
import java.util.function.Supplier;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@RestController
@CrossOrigin("*")
public class AuthController {

    private JwtEncoder jwtEncoder;
    private UserDetailsService userDetailsService;
    private JwtDecoder jwtDecoder;
    private AuthenticationManager authenticationManager;
    private TokenService tokenService;
    private AccountService accountService;

    public AuthController(JwtEncoder jwtEncoder, UserDetailsService userDetailsService,JwtDecoder jwtDecoder, AuthenticationManager authenticationManager, TokenService tokenService, AccountService accountService) {
        this.jwtEncoder = jwtEncoder;


        this.jwtDecoder = jwtDecoder;
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
        this.accountService = accountService;
    }

    @PostMapping("/token")
    public ResponseEntity< Map<String,String>>jwtToken(@RequestBody()LoginRequest loginRequest){
        Authentication authentication=null;
        Map<String,String > response;
        if(loginRequest.grantType().equals("password")) {
            try {
                 authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password())
                );
            }catch (Exception e){
                return new
                        ResponseEntity<>(Map.of("errorMesage",e.getMessage()), HttpStatus.UNAUTHORIZED);
            }

           response= tokenService.generateToken(authentication.getName(),
                                       authentication.getAuthorities(),
                                       loginRequest.withRefreshToken());
           return ResponseEntity.ok(response);
        }
        else if(loginRequest.grantType().equals("refreshToken")){
            if(loginRequest.refreshToken()==null){
                return new
                        ResponseEntity<>(Map.of("errorMesage","Refresh Token is required"), HttpStatus.UNAUTHORIZED);
            }
//exception de expired refreshtoken a gerer apres
            Jwt decodeJwt =null;
            try {
                decodeJwt = jwtDecoder.decode(loginRequest.refreshToken());
            }catch (JwtException e){
                return new ResponseEntity<>(Map.of("errorMesage",e.getMessage()), HttpStatus.UNAUTHORIZED);
            }
            String subject=decodeJwt.getSubject();

            AppUser appUser=accountService.findByUserName(subject);
            Collection<? extends GrantedAuthority>
                    authorities = appUser.getAppRoles()
                    .stream().map(r->new SimpleGrantedAuthority(r.getRoleName()))
                    .collect(Collectors.toList());

            response= tokenService.generateToken(subject,
                    authorities,
                    loginRequest.withRefreshToken());
            return ResponseEntity.ok(response);
        }

        return new ResponseEntity(Map.of("error",
                String.format("grantType <<%s>> not supported ",
                        loginRequest.grantType())),HttpStatus.UNAUTHORIZED);

}




}
