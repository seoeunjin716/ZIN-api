package com.seoeunjin.api.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 레거시/혼재된 OAuth 콜백 경로를 현재 구현으로 연결하는 브릿지 컨트롤러.
 *
 * 배포/로컬/개발자 콘솔 설정이 서로 다른 콜백 경로를 가리킬 때
 * Spring Whitelabel 404가 발생할 수 있어, 아래 경로들을 실제 콜백 경로로 리다이렉트합니다.
 *
 * NOTE: 여기서는 검증을 하지 않고 단순히 라우팅만 합니다.
 */
@Controller
public class LegacyOAuthCallbackController {

    @GetMapping({ "/auth/naver/callback", "/api/auth/naver/callback" })
    public String redirectToCurrentNaverCallback(HttpServletRequest request) {
        String query = request.getQueryString();
        if (query == null || query.isBlank()) {
            return "redirect:/naver/callback";
        }
        return "redirect:/naver/callback?" + query;
    }

    @GetMapping({ "/auth/google/callback", "/api/auth/google/callback" })
    public String redirectToCurrentGoogleCallback(HttpServletRequest request) {
        String query = request.getQueryString();
        if (query == null || query.isBlank()) {
            return "redirect:/google/callback";
        }
        return "redirect:/google/callback?" + query;
    }
}
