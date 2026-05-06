package com.mini.logoutsystem.controller;

import com.mini.logoutsystem.util.JwtUtil;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final JwtUtil jwtUtil;

    public AuthController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/login/{username}")
    public String login(@PathVariable String username) {
        return jwtUtil.generateToken(username);
    }
}