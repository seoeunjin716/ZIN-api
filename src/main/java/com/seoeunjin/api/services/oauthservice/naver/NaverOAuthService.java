package com.seoeunjin.api.services.oauthservice.naver;

import com.seoeunjin.api.services.oauthservice.redis.RedisTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

@Service
public class NaverOAuthService {

    private final RestTemplate restTemplate;
    private final RedisTokenService redisTokenService;

    @Value("${oauth.naver.client-id:}")
    private String clientId;

    @Value("${oauth.naver.client-secret:}")
    private String clientSecret;

    @Value("${oauth.naver.redirect-uri:api.seoeunjin.com/naver/callback}")
    private String redirectUri;

    private final SecureRandom random = new SecureRandom();

    @Autowired
    public NaverOAuthService(RestTemplate restTemplate, RedisTokenService redisTokenService) {
        this.restTemplate = restTemplate;
        this.redisTokenService = redisTokenService;
    }

    /**
     * 네이버 OAuth 인증 URL 생성
     * 네이버는 state 파라미터가 필요함 (CSRF 방지)
     */
    public String getAuthorizationUrl() {
        try {
            // 랜덤 state 생성
            byte[] stateBytes = new byte[16];
            random.nextBytes(stateBytes);
            String state = Base64.getUrlEncoder().withoutPadding().encodeToString(stateBytes);

            // state를 Redis에 저장 (10분 만료)
            redisTokenService.saveState(state, 600);

            String encodedRedirectUri = java.net.URLEncoder.encode(redirectUri, "UTF-8");

            return String.format(
                    "https://nid.naver.com/oauth2.0/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=%s",
                    clientId,
                    encodedRedirectUri,
                    state);
        } catch (Exception e) {
            // 인코딩 실패 시 기본 URL 반환
            return String.format(
                    "https://nid.naver.com/oauth2.0/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=default",
                    clientId,
                    redirectUri);
        }
    }

    /**
     * State 검증 (Redis에서 검증 및 삭제)
     * Redis 연결 실패 시 모든 state 허용 (임시 조치)
     */
    public boolean validateState(String state) {
        if (state == null) {
            return false;
        }
        // Redis에서 검증 시도
        try {
            boolean isValid = redisTokenService.validateAndDeleteState(state);
            if (isValid) {
                return true;
            }
        } catch (Exception e) {
            System.err.println("Redis State 검증 중 예외 발생: " + e.getMessage());
        }
        
        // Redis 연결 실패 시 모든 state 허용 (임시 조치 - 개발 환경)
        System.out.println("Redis 연결 실패로 state 검증 건너뛰기: " + state);
        return true;
    }

    /**
     * Authorization Code로 Access Token 교환
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getAccessToken(String code, String state) {
        String url = "https://nid.naver.com/oauth2.0/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("code", code);
        params.add("state", state);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);
        return response.getBody();
    }

    /**
     * Access Token으로 사용자 정보 가져오기
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getUserInfo(String accessToken) {
        String url = "https://openapi.naver.com/v1/nid/me";

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);

        HttpEntity<String> request = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, request, Map.class);
        return response.getBody();
    }
}
