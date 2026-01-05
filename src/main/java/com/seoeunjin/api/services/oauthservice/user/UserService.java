package com.seoeunjin.api.services.oauthservice.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;

    @Autowired
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * 카카오 ID로 사용자 찾기 또는 생성
     */
    @Transactional
    public User findOrCreateKakaoUser(String kakaoId, String email, String name, String nickname, String profileImage) {
        Optional<User> existingUser = userRepository.findByKakaoIdAndProvider(kakaoId, "kakao");
        
        if (existingUser.isPresent()) {
            User user = existingUser.get();
            // 정보 업데이트
            if (email != null && !email.isEmpty()) {
                user.setEmail(email);
            }
            if (name != null && !name.isEmpty()) {
                user.setName(name);
            }
            if (nickname != null && !nickname.isEmpty()) {
                user.setNickname(nickname);
            }
            if (profileImage != null && !profileImage.isEmpty()) {
                user.setProfileImage(profileImage);
            }
            return userRepository.save(user);
        } else {
            // 새 사용자 생성
            User newUser = new User();
            newUser.setKakaoId(kakaoId);
            newUser.setEmail(email);
            newUser.setName(name != null ? name : nickname);
            newUser.setNickname(nickname);
            newUser.setProfileImage(profileImage);
            newUser.setProvider("kakao");
            return userRepository.save(newUser);
        }
    }

    /**
     * 네이버 ID로 사용자 찾기 또는 생성 (kakaoId 필드 재사용, provider로 구분)
     */
    @Transactional
    public User findOrCreateNaverUser(String naverId, String email, String name, String nickname, String profileImage) {
        Optional<User> existingUser = userRepository.findByKakaoIdAndProvider(naverId, "naver");
        
        if (existingUser.isPresent()) {
            User user = existingUser.get();
            // 정보 업데이트
            if (email != null && !email.isEmpty()) {
                user.setEmail(email);
            }
            if (name != null && !name.isEmpty()) {
                user.setName(name);
            }
            if (nickname != null && !nickname.isEmpty()) {
                user.setNickname(nickname);
            }
            if (profileImage != null && !profileImage.isEmpty()) {
                user.setProfileImage(profileImage);
            }
            return userRepository.save(user);
        } else {
            // 새 사용자 생성
            User newUser = new User();
            newUser.setKakaoId(naverId); // kakaoId 필드 재사용 (provider로 구분)
            newUser.setEmail(email);
            newUser.setName(name != null ? name : nickname);
            newUser.setNickname(nickname);
            newUser.setProfileImage(profileImage);
            newUser.setProvider("naver");
            return userRepository.save(newUser);
        }
    }

    /**
     * 구글 ID로 사용자 찾기 또는 생성 (kakaoId 필드 재사용, provider로 구분)
     */
    @Transactional
    public User findOrCreateGoogleUser(String googleId, String email, String name, String nickname, String profileImage) {
        Optional<User> existingUser = userRepository.findByKakaoIdAndProvider(googleId, "google");
        
        if (existingUser.isPresent()) {
            User user = existingUser.get();
            // 정보 업데이트
            if (email != null && !email.isEmpty()) {
                user.setEmail(email);
            }
            if (name != null && !name.isEmpty()) {
                user.setName(name);
            }
            if (nickname != null && !nickname.isEmpty()) {
                user.setNickname(nickname);
            }
            if (profileImage != null && !profileImage.isEmpty()) {
                user.setProfileImage(profileImage);
            }
            return userRepository.save(user);
        } else {
            // 새 사용자 생성
            User newUser = new User();
            newUser.setKakaoId(googleId); // kakaoId 필드 재사용 (provider로 구분)
            newUser.setEmail(email);
            newUser.setName(name != null ? name : nickname);
            newUser.setNickname(nickname);
            newUser.setProfileImage(profileImage);
            newUser.setProvider("google");
            return userRepository.save(newUser);
        }
    }
}

