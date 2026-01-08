package com.seoeunjin.api.services.oauthservice.redis;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * OAuth 토큰을 Redis에 저장하고 조회하는 서비스
 */
@Service
public class RedisTokenService {

    private final StringRedisTemplate redisTemplate;

    @Autowired
    public RedisTokenService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * OAuth 제공자 원본 토큰 저장
     * 
     * @param provider OAuth 제공자 (google, kakao, naver)
     * @param userId 사용자 ID
     * @param accessToken Access Token
     * @param refreshToken Refresh Token
     * @param expirationSeconds 만료 시간 (초)
     */
    public void saveOAuthToken(String provider, String userId, String accessToken, String refreshToken, long expirationSeconds) {
        try {
            String accessKey = String.format("oauth:%s:%s:access", provider, userId);
            String refreshKey = String.format("oauth:%s:%s:refresh", provider, userId);
            
            redisTemplate.opsForValue().set(accessKey, accessToken, expirationSeconds, TimeUnit.SECONDS);
            if (refreshToken != null && !refreshToken.isEmpty()) {
                // Refresh Token은 더 긴 만료 시간 (30일)
                redisTemplate.opsForValue().set(refreshKey, refreshToken, 30, TimeUnit.DAYS);
            }
        } catch (Exception e) {
            System.err.println("Redis OAuth 토큰 저장 실패 (계속 진행): " + e.getMessage());
            // Redis 연결 실패 시에도 계속 진행 (선택적 기능)
        }
    }

    /**
     * OAuth 제공자 원본 Access Token 조회
     */
    public String getOAuthAccessToken(String provider, String userId) {
        String key = String.format("oauth:%s:%s:access", provider, userId);
        return redisTemplate.opsForValue().get(key);
    }

    /**
     * OAuth 제공자 원본 Refresh Token 조회
     */
    public String getOAuthRefreshToken(String provider, String userId) {
        String key = String.format("oauth:%s:%s:refresh", provider, userId);
        return redisTemplate.opsForValue().get(key);
    }

    /**
     * JWT 토큰 저장
     * 
     * @param provider OAuth 제공자
     * @param userId 사용자 ID
     * @param accessToken JWT Access Token
     * @param refreshToken JWT Refresh Token
     * @param expirationSeconds 만료 시간 (초)
     */
    public void saveJwtToken(String provider, String userId, String accessToken, String refreshToken, long expirationSeconds) {
        try {
            String accessKey = String.format("token:%s:%s:access", provider, userId);
            String refreshKey = String.format("token:%s:%s:refresh", provider, userId);
            
            redisTemplate.opsForValue().set(accessKey, accessToken, expirationSeconds, TimeUnit.SECONDS);
            if (refreshToken != null && !refreshToken.isEmpty()) {
                // Refresh Token은 더 긴 만료 시간 (30일)
                redisTemplate.opsForValue().set(refreshKey, refreshToken, 30, TimeUnit.DAYS);
            }
        } catch (Exception e) {
            System.err.println("Redis JWT 토큰 저장 실패 (계속 진행): " + e.getMessage());
            // Redis 연결 실패 시에도 계속 진행 (선택적 기능)
        }
    }

    /**
     * ✅ 요구사항: accessToken을 Upstash Redis에 "메일주소와 함께" 저장
     * - 키는 provider + email 기반으로 고정해서 Upstash Data Browser에서 찾기 쉽게 함
     * - 값은 JSON 문자열(간단)
     */
    public void saveAccessTokenWithEmail(String provider, String email, String accessToken, long expirationSeconds) {
        try {
            String safeEmail = email == null ? "" : email.trim().toLowerCase();
            String key = String.format("access:%s:%s", provider, safeEmail);
            String value = String.format("{\"provider\":\"%s\",\"email\":\"%s\",\"accessToken\":\"%s\"}",
                    provider,
                    safeEmail.replace("\"", "\\\""),
                    accessToken == null ? "" : accessToken.replace("\"", "\\\""));
            redisTemplate.opsForValue().set(key, value, expirationSeconds, TimeUnit.SECONDS);
        } catch (Exception e) {
            System.err.println("Redis accessToken(email 포함) 저장 실패 (계속 진행): " + e.getMessage());
        }
    }

    public void deleteAccessTokenByEmail(String provider, String email) {
        try {
            String safeEmail = email == null ? "" : email.trim().toLowerCase();
            String key = String.format("access:%s:%s", provider, safeEmail);
            redisTemplate.delete(key);
        } catch (Exception e) {
            System.err.println("Redis accessToken(email 기반) 삭제 실패 (계속 진행): " + e.getMessage());
        }
    }

    /**
     * JWT Access Token 조회
     */
    public String getJwtAccessToken(String provider, String userId) {
        String key = String.format("token:%s:%s:access", provider, userId);
        return redisTemplate.opsForValue().get(key);
    }

    /**
     * JWT Refresh Token 조회
     */
    public String getJwtRefreshToken(String provider, String userId) {
        String key = String.format("token:%s:%s:refresh", provider, userId);
        return redisTemplate.opsForValue().get(key);
    }

    /**
     * 토큰 삭제 (로그아웃 시 사용)
     */
    public void deleteTokens(String provider, String userId) {
        String oauthAccessKey = String.format("oauth:%s:%s:access", provider, userId);
        String oauthRefreshKey = String.format("oauth:%s:%s:refresh", provider, userId);
        String jwtAccessKey = String.format("token:%s:%s:access", provider, userId);
        String jwtRefreshKey = String.format("token:%s:%s:refresh", provider, userId);
        
        redisTemplate.delete(oauthAccessKey);
        redisTemplate.delete(oauthRefreshKey);
        redisTemplate.delete(jwtAccessKey);
        redisTemplate.delete(jwtRefreshKey);
    }

    /**
     * State 저장 (OAuth CSRF 방지용)
     * 
     * @param state State 값
     * @param expirationSeconds 만료 시간 (초, 기본 10분)
     */
    public void saveState(String state, long expirationSeconds) {
        try {
            String key = String.format("oauth:state:%s", state);
            redisTemplate.opsForValue().set(key, "valid", expirationSeconds, TimeUnit.SECONDS);
        } catch (Exception e) {
            System.err.println("Redis State 저장 실패 (계속 진행): " + e.getMessage());
            // Redis 연결 실패 시에도 계속 진행 (선택적 기능)
        }
    }

    /**
     * State 검증 및 삭제
     * 
     * @param state State 값
     * @return 유효한 state인지 여부
     */
    public boolean validateAndDeleteState(String state) {
        try {
            String key = String.format("oauth:state:%s", state);
            String value = redisTemplate.opsForValue().get(key);
            if (value != null && "valid".equals(value)) {
                redisTemplate.delete(key);
                return true;
            }
            return false;
        } catch (Exception e) {
            System.err.println("Redis State 검증 실패: " + e.getMessage());
            // Redis 연결 실패 시 false 반환 (보안상 안전)
            return false;
        }
    }
}

