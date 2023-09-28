package com.jwt.Authentication.auth.DTO;

public record LoginRequest( String grantType,
                            String username,
                            String password,
                            boolean withRefreshToken,
                            String refreshToken) {
}
