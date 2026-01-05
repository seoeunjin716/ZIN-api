package com.seoeunjin.api.services.oauthservice.kakao;

import com.seoeunjin.api.services.oauthservice.jwt.JwtTokenProvider;
import com.seoeunjin.api.services.oauthservice.user.User;
import com.seoeunjin.api.services.oauthservice.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/kakao")
public class KakaoController {

    private final KakaoOAuthService kakaoOAuthService;
    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;

    @Autowired
    public KakaoController(KakaoOAuthService kakaoOAuthService,
            UserService userService,
            JwtTokenProvider jwtTokenProvider) {
        this.kakaoOAuthService = kakaoOAuthService;
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
        System.out.println("KakaoController 초기화됨");
    }

    /**
     * 카카오 로그인 시작 - OAuth 인증 URL로 리다이렉트
     */
    @GetMapping("/login")
    public void kakaoLogin(HttpServletResponse response) throws Exception {
        System.out.println("==================== 카카오 로그인 GET 요청 들어옴 ====================");
        System.out.println("로그인 성공!");
        System.out.flush();
        String authUrl = kakaoOAuthService.getAuthorizationUrl();
        response.sendRedirect(authUrl);
    }

    /**
     * 카카오 OAuth 콜백 - 실제 OAuth 플로우 처리
     */
    @GetMapping("/callback")
    public void kakaoCallback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String error,
            HttpServletResponse response) {

        System.out.println("==================== 카카오 콜백 요청 들어옴 ====================");
        System.out.flush();

        if (error != null) {
            try {
                response.sendRedirect("http://localhost:3000/login?error=kakao_cancel");
            } catch (Exception e) {
                // ignore
            }
            return;
        }

        if (code == null) {
            try {
                response.sendRedirect("http://localhost:3000/login?error=kakao_no_code");
            } catch (Exception e) {
                // ignore
            }
            return;
        }

        try {
            // Access Token 획득
            Map<String, Object> tokenResponse = kakaoOAuthService.getAccessToken(code);

            if (tokenResponse == null || !tokenResponse.containsKey("access_token")) {
                System.err.println("카카오 Access Token 응답 오류: " + tokenResponse);
                response.sendRedirect("http://localhost:3000/login?error=kakao_token_failed");
                return;
            }

            String accessToken = (String) tokenResponse.get("access_token");
            System.out.println("카카오 Access Token 획득 성공");

            // 사용자 정보 조회
            Map<String, Object> userInfo = kakaoOAuthService.getUserInfo(accessToken);

            // 카카오 사용자 정보에서 데이터 추출
            // 카카오 응답 구조: { "id": ..., "kakao_account": { "email": ..., "profile": {
            // "nickname": ... } } }
            String kakaoId = String.valueOf(((Number) userInfo.get("id")).longValue());
            Map<String, Object> kakaoAccount = (Map<String, Object>) userInfo.get("kakao_account");

            String email = null;
            String nickname = null;
            String profileImage = null;
            String name = null;

            if (kakaoAccount != null) {
                email = (String) kakaoAccount.get("email");
                Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");
                if (profile != null) {
                    nickname = (String) profile.get("nickname");
                    profileImage = (String) profile.get("profile_image_url");
                }
                name = (String) kakaoAccount.get("name");
            }

            Map<String, Object> properties = (Map<String, Object>) userInfo.get("properties");
            if (properties != null && nickname == null) {
                nickname = (String) properties.get("nickname");
                if (profileImage == null) {
                    profileImage = (String) properties.get("profile_image");
                }
            }

            // 사용자 찾기 또는 생성
            User user = userService.findOrCreateKakaoUser(
                    kakaoId,
                    email != null ? email : "",
                    name != null ? name : (nickname != null ? nickname : "카카오사용자"),
                    nickname != null ? nickname : "카카오사용자",
                    profileImage != null ? profileImage : "");

            // JWT 토큰 생성 (User ID, 이메일, 이름, 제공자 정보 포함)
            String jwtToken = jwtTokenProvider.generateToken(
                    user.getId(),
                    user.getEmail() != null ? user.getEmail() : "",
                    user.getName() != null ? user.getName() : user.getNickname(),
                    "kakao");

            // 쿠키 설정
            String cookie = String.format(
                    "access_token=%s; Path=/; Domain=localhost; Max-Age=86400; HttpOnly; SameSite=Lax",
                    jwtToken);
            response.setHeader("Set-Cookie", cookie);

            // 로그인 성공 메시지 출력
            System.out.println("카카오 로그인 성공! 사용자 ID: " + user.getId() + ", 카카오 ID: " + kakaoId);

            response.sendRedirect("http://localhost:3000/dashboard/kakao");

        } catch (Exception e) {
            System.err.println("카카오 OAuth 인증 실패: " + e.getMessage());
            e.printStackTrace();
            try {
                response.sendRedirect("http://localhost:3000/login?error=kakao_auth_failed&message=" +
                        URLEncoder.encode(e.getMessage(), "UTF-8"));
            } catch (Exception ex) {
                // ignore
            }
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> kakaoLoginPost(
            @RequestBody(required = false) Map<String, Object> request) {
        System.out.println("==================== 카카오 로그인 POST 요청 들어옴 ====================");
        System.out.println("😎😎😎😎😎😎 카카오 로그인 진입 " + request);
        System.out.flush();

        // 카카오 OAuth 인증 URL 생성
        String authUrl = kakaoOAuthService.getAuthorizationUrl();

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "카카오 인증 URL 생성");
        response.put("authUrl", authUrl); // 프론트엔드가 이 URL로 리다이렉트

        System.out.println("😎😎😎😎😎😎 카카오 OAuth URL: " + authUrl);
        System.out.flush();

        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}