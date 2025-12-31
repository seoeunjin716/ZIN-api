package com.seoeunjin.api.google;

import com.seoeunjin.api.jwt.JwtTokenProvider;
import com.seoeunjin.api.user.User;
import com.seoeunjin.api.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/google")
public class GoogleController {

    private final GoogleOAuthService googleOAuthService;
    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;

    @Autowired
    public GoogleController(GoogleOAuthService googleOAuthService,
            UserService userService,
            JwtTokenProvider jwtTokenProvider) {
        this.googleOAuthService = googleOAuthService;
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
        System.out.println("GoogleController 초기화됨");
    }

    /**
     * 구글 로그인 시작 - OAuth 인증 URL로 리다이렉트
     */
    @GetMapping("/login")
    public void googleLogin(HttpServletResponse response) throws Exception {
        System.out.println("==================== 구글 로그인 GET 요청 들어옴 ====================");
        System.out.println("로그인 성공!");
        System.out.flush();
        String authUrl = googleOAuthService.getAuthorizationUrl();
        response.sendRedirect(authUrl);
    }

    /**
     * 구글 OAuth 콜백 - 실제 OAuth 플로우 처리
     */
    @GetMapping("/callback")
    public void googleCallback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String error,
            HttpServletResponse response) {

        System.out.println("==================== 구글 콜백 요청 들어옴 ====================");
        System.out.flush();

        if (error != null) {
            try {
                response.sendRedirect("http://localhost:3000/login?error=google_cancel");
            } catch (Exception e) {
                // ignore
            }
            return;
        }

        if (code == null) {
            try {
                response.sendRedirect("http://localhost:3000/login?error=google_no_code");
            } catch (Exception e) {
                // ignore
            }
            return;
        }

        try {
            // Access Token 획득
            Map<String, Object> tokenResponse = googleOAuthService.getAccessToken(code);

            if (tokenResponse == null || !tokenResponse.containsKey("access_token")) {
                System.err.println("구글 Access Token 응답 오류: " + tokenResponse);
                response.sendRedirect("http://localhost:3000/login?error=google_token_failed");
                return;
            }

            String accessToken = (String) tokenResponse.get("access_token");
            System.out.println("구글 Access Token 획득 성공");

            // 사용자 정보 조회
            Map<String, Object> userInfo = googleOAuthService.getUserInfo(accessToken);

            // 구글 사용자 정보에서 데이터 추출
            // 구글 응답 구조: { "id": ..., "email": ..., "name": ..., "picture": ...,
            // "verified_email": ... }
            String googleId = (String) userInfo.get("id");
            String email = (String) userInfo.get("email");
            String name = (String) userInfo.get("name");
            String picture = (String) userInfo.get("picture");
            String givenName = (String) userInfo.get("given_name");
            String familyName = (String) userInfo.get("family_name");

            // 사용자 찾기 또는 생성
            User user = userService.findOrCreateGoogleUser(
                    googleId,
                    email != null ? email : "",
                    name != null ? name
                            : (givenName != null ? givenName + (familyName != null ? " " + familyName : "") : "구글사용자"),
                    name != null ? name : "구글사용자",
                    picture != null ? picture : "");

            // JWT 토큰 생성 (User ID, 이메일, 이름, 제공자 정보 포함)
            String jwtToken = jwtTokenProvider.generateToken(
                    user.getId(),
                    user.getEmail() != null ? user.getEmail() : "",
                    user.getName() != null ? user.getName() : user.getNickname(),
                    "google");

            // 쿠키 설정
            String cookie = String.format(
                    "access_token=%s; Path=/; Domain=localhost; Max-Age=86400; HttpOnly; SameSite=Lax",
                    jwtToken);
            response.setHeader("Set-Cookie", cookie);

            // 로그인 성공 메시지 출력
            System.out.println("구글 로그인 성공! 사용자 ID: " + user.getId() + ", 구글 ID: " + googleId);

            response.sendRedirect("http://localhost:3000/dashboard/google");

        } catch (Exception e) {
            System.err.println("구글 OAuth 인증 실패: " + e.getMessage());
            e.printStackTrace();
            try {
                response.sendRedirect("http://localhost:3000/login?error=google_auth_failed&message=" +
                        URLEncoder.encode(e.getMessage(), "UTF-8"));
            } catch (Exception ex) {
                // ignore
            }
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> googleLoginPost(
            @RequestBody(required = false) Map<String, Object> request) {
        System.out.println("==================== 구글 로그인 POST 요청 들어옴 ====================");
        System.out.println("😎😎😎😎😎😎 구글 로그인 진입 " + request);
        System.out.flush();

        // 구글 OAuth 인증 URL 생성
        String authUrl = googleOAuthService.getAuthorizationUrl();

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "구글 인증 URL 생성");
        response.put("authUrl", authUrl); // 프론트엔드가 이 URL로 리다이렉트

        System.out.println("😎😎😎😎😎😎 구글 OAuth URL: " + authUrl);
        System.out.flush();

        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}
