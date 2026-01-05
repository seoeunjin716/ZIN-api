package com.seoeunjin.api.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/gateway")
public class GatewayController {

    public GatewayController() {
        System.out.println("=".repeat(80));
        System.out.println("GatewayController 초기화됨");
        System.out.println("📡 Endpoint: GET /api/gateway/status - 게이트웨이 상태 확인");
        System.out.println("=".repeat(80));
        System.out.flush();
    }

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("status", "ok");
        status.put("message", "Gateway is running");
        status.put("timestamp", LocalDateTime.now());

        return ResponseEntity.ok(status);
    }
}
