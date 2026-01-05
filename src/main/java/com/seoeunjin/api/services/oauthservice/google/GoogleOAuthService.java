package com.seoeunjin.api.services.oauthservice.google;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class GoogleOAuthService {

    private final RestTemplate restTemplate;
    
    @Value("${google.client-id:}")
    private String clientId;
    
    @Value("${google.client-secret:}")
    private String clientSecret;
    
    @Value("${google.redirect-uri:http://localhost:8080/google/callback}")
    private String redirectUri;

    @Autowired
    public GoogleOAuthService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * 구글 OAuth 인증 URL 생성
     * scope: openid, email, profile (이메일, 프로필 정보 권한)
     */
    public String getAuthorizationUrl() {
        try {
            String scope = "openid email profile";
            String encodedRedirectUri = java.net.URLEncoder.encode(redirectUri, "UTF-8");
            String encodedScope = java.net.URLEncoder.encode(scope, "UTF-8");
            
            return String.format(
                "https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=%s",
                clientId,
                encodedRedirectUri,
                encodedScope
            );
        } catch (Exception e) {
            // 인코딩 실패 시 기본 URL 반환
            return String.format(
                "https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=openid%%20email%%20profile",
                clientId,
                redirectUri
            );
        }
    }

    /**
     * Authorization Code로 Access Token 교환
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getAccessToken(String code) {
        String url = "https://oauth2.googleapis.com/token";
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("redirect_uri", redirectUri);
        params.add("grant_type", "authorization_code");
        
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        
        ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);
        return response.getBody();
    }

    /**
     * Access Token으로 사용자 정보 가져오기
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getUserInfo(String accessToken) {
        String url = "https://www.googleapis.com/oauth2/v2/userinfo";
        
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        
        HttpEntity<String> request = new HttpEntity<>(headers);
        
        ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, request, Map.class);
        return response.getBody();
    }
}

