package com.seoeunjin.api.services.oauthservice.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private String secret;
    private Long accessTokenExpiration;
    private Long refreshTokenExpiration;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public Long getAccessTokenExpiration() {
        return accessTokenExpiration != null ? accessTokenExpiration : 3600000L; // 기본 1시간
    }

    public void setAccessTokenExpiration(Long accessTokenExpiration) {
        this.accessTokenExpiration = accessTokenExpiration;
    }

    public Long getRefreshTokenExpiration() {
        return refreshTokenExpiration != null ? refreshTokenExpiration : 2592000000L; // 기본 30일
    }

    public void setRefreshTokenExpiration(Long refreshTokenExpiration) {
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    // 하위 호환성을 위한 메서드
    @Deprecated
    public Long getExpiration() {
        return getAccessTokenExpiration();
    }
}

