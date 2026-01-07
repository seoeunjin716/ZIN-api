package com.seoeunjin.api.services.oauthservice.google;

import com.seoeunjin.api.services.oauthservice.jwt.JwtTokenProvider;
import com.seoeunjin.api.services.oauthservice.redis.RedisTokenService;
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
@RequestMapping("/google")
public class GoogleController {

    private final GoogleOAuthService googleOAuthService;
    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTokenService redisTokenService;

    @Autowired
    public GoogleController(GoogleOAuthService googleOAuthService,
            UserService userService,
            JwtTokenProvider jwtTokenProvider,
            RedisTokenService redisTokenService) {
        this.googleOAuthService = googleOAuthService;
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
        this.redisTokenService = redisTokenService;
        System.out.println("GoogleController 초기화됨");
    }

    /**
     * 사용자 정보 조회 (JWT 토큰에서)
     */
    @GetMapping("/user")
    public ResponseEntity<Map<String, Object>> getUserInfo(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        Map<String, Object> response = new HashMap<>();

        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                response.put("success", false);
                response.put("message", "인증 토큰이 없습니다.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            String token = authHeader.substring(7);
            if (!jwtTokenProvider.validateToken(token)) {
                response.put("success", false);
                response.put("message", "유효하지 않은 토큰입니다.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            Long userId = jwtTokenProvider.getUserIdFromToken(token);
            User user = userService.findById(userId);
            if (user == null) {
                response.put("success", false);
                response.put("message", "사용자를 찾을 수 없습니다.");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
            }

            Map<String, Object> userData = new HashMap<>();
            // googleId는 users.kakaoId 필드에 저장되어 있음 (provider로 구분)
            userData.put("id", user.getKakaoId());
            userData.put("nickname", user.getNickname() != null ? user.getNickname() : user.getName());
            userData.put("email", user.getEmail());
            userData.put("provider", "google");

            response.put("success", true);
            response.put("user", userData);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "사용자 정보 조회 실패: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * 로그아웃 - 쿠키 삭제 및 Redis 토큰 삭제
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        Map<String, Object> response = new HashMap<>();
        try {
            // JWT 토큰에서 사용자 정보 추출 (선택적)
            // 쿠키는 클라이언트에서 삭제해야 함
            response.put("success", true);
            response.put("message", "로그아웃 성공");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "로그아웃 실패: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
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
            String refreshToken = (String) tokenResponse.get("refresh_token");
            Object expiresInObj = tokenResponse.get("expires_in");
            long expiresIn = expiresInObj != null ? Long.parseLong(expiresInObj.toString()) : 3600; // 기본 1시간
            
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
            
            // JWT Refresh Token 생성 (간단히 access token과 동일하게, 실제로는 별도 생성 로직 필요)
            String jwtRefreshToken = jwtToken; // TODO: 실제 Refresh Token 생성 로직 구현 필요

            // OAuth 원본 토큰을 Redis에 저장
            redisTokenService.saveOAuthToken(
                    "google",
                    googleId,
                    accessToken,
                    refreshToken,
                    expiresIn
            );

            // JWT 토큰을 Redis에 저장 (1시간 만료)
            redisTokenService.saveJwtToken(
                    "google",
                    user.getId().toString(),
                    jwtToken,
                    jwtRefreshToken,
                    3600 // 1시간
            );

            // 쿠키 설정
            String cookie = String.format(
                    "access_token=%s; Path=/; Domain=localhost; Max-Age=86400; HttpOnly; SameSite=Lax",
                    jwtToken);
            response.setHeader("Set-Cookie", cookie);

            // 로그인 성공 메시지 출력
            System.out.println("구글 로그인 성공! 사용자 ID: " + user.getId() + ", 구글 ID: " + googleId);
            
            // 프론트엔드로 토큰과 함께 리다이렉트 (provider 포함)
            String redirectUrl = String.format(
                    "http://localhost:3000/?token=%s&refresh_token=%s&provider=google",
                    URLEncoder.encode(jwtToken, "UTF-8"),
                    URLEncoder.encode(jwtRefreshToken, "UTF-8"));
            response.sendRedirect(redirectUrl);

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
