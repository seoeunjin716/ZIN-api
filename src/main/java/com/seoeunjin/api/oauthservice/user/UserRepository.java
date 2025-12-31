package com.seoeunjin.api.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByKakaoIdAndProvider(String kakaoId, String provider);
    Optional<User> findByEmailAndProvider(String email, String provider);
}

