package com.seoeunjin.api.services.oauthservice.kakao;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class KakaoOAuthService {

    private final RestTemplate restTemplate;
    
    @Value("${oauth.kakao.rest-api-key:}")
    private String clientId;
    
    @Value("${KAKAO_REST_API_KEY:}")
    private String restApiKey;
    
    @Value("${oauth.kakao.client-secret:}")
    private String clientSecret;
    
    @Value("${oauth.kakao.redirect-uri:http://localhost:8080/kakao/callback}")
    private String redirectUri;

    @Autowired
    public KakaoOAuthService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
        // KAKAO_REST_API_KEY가 설정되어 있으면 우선 사용
        if ((this.clientId == null || this.clientId.isEmpty()) && 
            (this.restApiKey != null && !this.restApiKey.isEmpty())) {
            this.clientId = this.restApiKey;
        }
    }

    /**
     * 카카오 OAuth 인증 URL 생성
     * scope: profile_nickname (기본 닉네임 권한)
     * 필요시 profile_image, account_email 추가 가능 (카카오 개발자 콘솔에서 동의 항목 설정 필요)
     */
    public String getAuthorizationUrl() {
        try {
            // 기본 scope만 요청 (필요시 카카오 개발자 콘솔에서 동의 항목 설정 후 추가)
            String scope = "profile_nickname";
            String encodedRedirectUri = java.net.URLEncoder.encode(redirectUri, "UTF-8");
            String encodedScope = java.net.URLEncoder.encode(scope, "UTF-8");
            
            return String.format(
                "https://kauth.kakao.com/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=%s",
                clientId,
                encodedRedirectUri,
                encodedScope
            );
        } catch (Exception e) {
            // 인코딩 실패 시 기본 URL 반환 (scope 없이)
            return String.format(
                "https://kauth.kakao.com/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code",
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
        String url = "https://kauth.kakao.com/oauth/token";
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("code", code);
        params.add("redirect_uri", redirectUri);
        
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        
        ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);
        return response.getBody();
    }

    /**
     * Access Token으로 사용자 정보 가져오기
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getUserInfo(String accessToken) {
        String url = "https://kapi.kakao.com/v2/user/me";
        
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        
        HttpEntity<String> request = new HttpEntity<>(headers);
        
        ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, request, Map.class);
        return response.getBody();
    }
}

