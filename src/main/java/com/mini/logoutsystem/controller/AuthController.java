package com.mini.logoutsystem.controller;

import com.mini.logoutsystem.service.TokenBlacklistService;
import com.mini.logoutsystem.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

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

            try {
                blacklistService.blacklistToken(token);
                logger.info("Token blacklisted successfully for logout");
                return "Logged out successfully";
            } catch (Exception e) {
                logger.error("Error blacklisting token (Redis issue?): {}", e.getMessage());
                logger.info("Logout processed (Note: Redis unavailable, token blacklist may not be persistent)");
                return "Logged out successfully (Note: Blacklist unavailable)";
            }
        }

        logger.warn("Logout attempt without Authorization header");
        return "No token found";
    }
}