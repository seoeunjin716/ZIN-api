package com.seoeunjin.api.services.oauthservice.naver;

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
@RequestMapping("/naver")
public class NaverController {

    private final NaverOAuthService naverOAuthService;
    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;

    @Autowired
    public NaverController(NaverOAuthService naverOAuthService,
            UserService userService,
            JwtTokenProvider jwtTokenProvider) {
        this.naverOAuthService = naverOAuthService;
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
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

            // 쿠키 설정
            String cookie = String.format(
                    "access_token=%s; Path=/; Domain=localhost; Max-Age=86400; HttpOnly; SameSite=Lax",
                    jwtToken);
            response.setHeader("Set-Cookie", cookie);

            // 로그인 성공 메시지 출력
            System.out.println("네이버 로그인 성공! 사용자 ID: " + user.getId() + ", 네이버 ID: " + naverId);

            response.sendRedirect("http://localhost:3000/dashboard/naver");

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
