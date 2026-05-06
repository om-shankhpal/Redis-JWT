package com.mini.logoutsystem.controller;

import com.mini.logoutsystem.service.TokenBlacklistService;
import com.mini.logoutsystem.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final JwtUtil jwtUtil;
    private final TokenBlacklistService blacklistService;

    public AuthController(JwtUtil jwtUtil, TokenBlacklistService blacklistService) {
        this.jwtUtil = jwtUtil;
        this.blacklistService = blacklistService;
    }

    @GetMapping("/login/{username}")
    public String login(@PathVariable String username) {
        return jwtUtil.generateToken(username);
    }

    @PostMapping("/logout")
    public String logout(HttpServletRequest request) {

        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {

            String token = authHeader.substring(7);

            blacklistService.blacklistToken(token);

            return "Logged out successfully";
        }

        return "No token found";
    }
}