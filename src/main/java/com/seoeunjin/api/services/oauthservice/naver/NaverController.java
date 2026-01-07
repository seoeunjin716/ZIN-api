package com.seoeunjin.api.services.oauthservice.naver;

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
@RequestMapping("/naver")
public class NaverController {

    private final NaverOAuthService naverOAuthService;
    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTokenService redisTokenService;

    @Autowired
    public NaverController(NaverOAuthService naverOAuthService,
            UserService userService,
            JwtTokenProvider jwtTokenProvider,
            RedisTokenService redisTokenService) {
        this.naverOAuthService = naverOAuthService;
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
        this.redisTokenService = redisTokenService;
        System.out.println("NaverController 초기화됨");
    }

    /**
     * 네이버 로그인 시작 - OAuth 인증 URL로 리다이렉트
     */
    @GetMapping("/login")
    public void naverLogin(HttpServletResponse response) throws Exception {
        System.out.println("==================== 네이버 로그인 GET 요청 들어옴 ====================");
        System.out.println("로그인 성공!");
        System.out.flush();
        String authUrl = naverOAuthService.getAuthorizationUrl();
        response.sendRedirect(authUrl);
    }

    /**
     * 네이버 OAuth 콜백 - 실제 OAuth 플로우 처리
     */
    @GetMapping("/callback")
    public void naverCallback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error,
            HttpServletResponse response) {

        System.out.println("==================== 네이버 콜백 요청 들어옴 ====================");
        System.out.flush();

        if (error != null) {
            try {
                response.sendRedirect("http://localhost:3000/?error=naver_cancel");
            } catch (Exception e) {
                // ignore
            }
            return;
        }

        if (code == null) {
            try {
                response.sendRedirect("http://localhost:3000/?error=naver_no_code");
            } catch (Exception e) {
                // ignore
            }
            return;
        }

        // State 검증
        if (state == null || !naverOAuthService.validateState(state)) {
            try {
                response.sendRedirect("http://localhost:3000/?error=naver_invalid_state");
            } catch (Exception e) {
                // ignore
            }
            return;
        }

        try {
            // Access Token 획득
            Map<String, Object> tokenResponse = naverOAuthService.getAccessToken(code, state);

            if (tokenResponse == null || !tokenResponse.containsKey("access_token")) {
                System.err.println("네이버 Access Token 응답 오류: " + tokenResponse);
                response.sendRedirect("http://localhost:3000/?error=naver_token_failed");
                return;
            }

            String accessToken = (String) tokenResponse.get("access_token");
            String refreshToken = (String) tokenResponse.get("refresh_token");
            Object expiresInObj = tokenResponse.get("expires_in");
            long expiresIn = expiresInObj != null ? Long.parseLong(expiresInObj.toString()) : 3600; // 기본 1시간
            
            System.out.println("네이버 Access Token 획득 성공");

            // 사용자 정보 조회
            Map<String, Object> userInfoResponse = naverOAuthService.getUserInfo(accessToken);

            // 네이버 응답 구조: { "response": { "id": ..., "email": ..., "name": ..., ... } }
            Map<String, Object> responseData = (Map<String, Object>) userInfoResponse.get("response");
            if (responseData == null) {
                System.err.println("네이버 사용자 정보 조회 실패: 응답 데이터 없음");
                response.sendRedirect("http://localhost:3000/?error=naver_no_user_info");
                return;
            }

            String naverId = (String) responseData.get("id");
            String email = (String) responseData.get("email");
            String name = (String) responseData.get("name");
            String nickname = (String) responseData.get("nickname");
            String profileImage = (String) responseData.get("profile_image");

            // 사용자 찾기 또는 생성
            User user = userService.findOrCreateNaverUser(
                    naverId,
                    email != null ? email : "",
                    name != null ? name : (nickname != null ? nickname : "네이버사용자"),
                    nickname != null ? nickname : "네이버사용자",
                    profileImage != null ? profileImage : "");

            // 사용자 ID 확인
            if (user == null || user.getId() == null) {
                System.err.println("네이버 사용자 생성 실패: 사용자 ID가 null입니다.");
                response.sendRedirect("http://localhost:3000/?error=naver_user_creation_failed");
                return;
            }

            // JWT 토큰 생성 (User ID, 이메일, 이름, 제공자 정보 포함)
            String jwtToken = jwtTokenProvider.generateToken(
                    user.getId(),
                    user.getEmail() != null ? user.getEmail() : "",
                    user.getName() != null ? user.getName() : user.getNickname(),
                    "naver");
            
            // JWT Refresh Token 생성 (간단히 access token과 동일하게, 실제로는 별도 생성 로직 필요)
            String jwtRefreshToken = jwtToken; // TODO: 실제 Refresh Token 생성 로직 구현 필요

            // OAuth 원본 토큰을 Redis에 저장
            redisTokenService.saveOAuthToken(
                    "naver",
                    naverId,
                    accessToken,
                    refreshToken,
                    expiresIn
            );

            // JWT 토큰을 Redis에 저장 (1시간 만료)
            redisTokenService.saveJwtToken(
                    "naver",
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
            System.out.println("네이버 로그인 성공! 사용자 ID: " + user.getId() + ", 네이버 ID: " + naverId);

            // 프론트엔드로 토큰과 함께 리다이렉트 (구글과 동일한 방식)
            String redirectUrl = String.format(
                    "http://localhost:3000/?token=%s&refresh_token=%s&provider=naver",
                    URLEncoder.encode(jwtToken, "UTF-8"),
                    URLEncoder.encode(jwtRefreshToken, "UTF-8"));
            response.sendRedirect(redirectUrl);

        } catch (Exception e) {
            System.err.println("네이버 OAuth 인증 실패: " + e.getMessage());
            e.printStackTrace();
            try {
                response.sendRedirect("http://localhost:3000/?error=naver_auth_failed&message=" +
                        URLEncoder.encode(e.getMessage(), "UTF-8"));
            } catch (Exception ex) {
                // ignore
            }
        }
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
            
            // JWT 토큰에서 사용자 정보 추출
            if (!jwtTokenProvider.validateToken(token)) {
                response.put("success", false);
                response.put("message", "유효하지 않은 토큰입니다.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            Long userId = jwtTokenProvider.getUserIdFromToken(token);
            String provider = jwtTokenProvider.getProviderFromToken(token);

            // DB에서 사용자 정보 조회
            User user = userService.findById(userId);
            if (user == null) {
                response.put("success", false);
                response.put("message", "사용자를 찾을 수 없습니다.");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
            }

            Map<String, Object> userData = new HashMap<>();
            userData.put("id", user.getId());
            userData.put("email", user.getEmail());
            userData.put("name", user.getName());
            userData.put("nickname", user.getNickname());
            userData.put("profile_image", user.getProfileImage());
            userData.put("provider", provider != null ? provider : "naver");

            response.put("success", true);
            response.put("user", userData);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            System.err.println("사용자 정보 조회 실패: " + e.getMessage());
            e.printStackTrace();
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
            // JWT 토큰에서 사용자 정보 추출하여 Redis 토큰 삭제 (선택적)
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                try {
                    Long userId = jwtTokenProvider.getUserIdFromToken(token);
                    String provider = jwtTokenProvider.getProviderFromToken(token);
                    if (userId != null && provider != null) {
                        redisTokenService.deleteTokens(provider, userId.toString());
                    }
                } catch (Exception e) {
                    System.err.println("Redis 토큰 삭제 실패: " + e.getMessage());
                }
            }
            response.put("success", true);
            response.put("message", "로그아웃 성공");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "로그아웃 실패: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> naverLoginPost(
            @RequestBody(required = false) Map<String, Object> request) {
        System.out.println("==================== 네이버 로그인 POST 요청 들어옴 ====================");
        System.out.println("😎😎😎😎😎😎 네이버 로그인 진입 " + request);
        System.out.flush();

        // 네이버 OAuth 인증 URL 생성
        String authUrl = naverOAuthService.getAuthorizationUrl();

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "네이버 인증 URL 생성");
        response.put("authUrl", authUrl); // 프론트엔드가 이 URL로 리다이렉트

        System.out.println("😎😎😎😎😎😎 네이버 OAuth URL: " + authUrl);
        System.out.flush();

        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}
