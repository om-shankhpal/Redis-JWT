package com.mini.logoutsystem.filter;

import com.mini.logoutsystem.service.TokenBlacklistService;
import com.mini.logoutsystem.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Collections;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

    private final JwtUtil jwtUtil;
    private final TokenBlacklistService blacklistService;

    public JwtFilter(JwtUtil jwtUtil, TokenBlacklistService blacklistService) {
        this.jwtUtil = jwtUtil;
        this.blacklistService = blacklistService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        String uri = request.getRequestURI();
        logger.info("Request URI: {}", uri);

        try {
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                logger.info("Authorization header found");

                String token = authHeader.substring(7);
                logger.debug("Token extracted, length: {}", token.length());

                try {
                    if (blacklistService.isBlacklisted(token)) {
                        logger.warn("Token is BLACKLISTED");
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        return;
                    }
                    logger.debug("✓ Token is not blacklisted");
                } catch (Exception e) {
                    logger.error("Error checking blacklist (Redis issue?): {}", e.getMessage());
                }

                if (jwtUtil.validateToken(token)) {
                    String username = jwtUtil.extractUsername(token);
                    logger.info("✓ Token is VALID for user: {}", username);

                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(username, null,  Collections.singletonList(() -> "ROLE_USER"));

                    authentication.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    logger.info("✓ Authentication set in SecurityContext for user: {}", username);

                } else {
                    logger.warn("Token validation FAILED");
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
            }else {
                logger.info("✓ Public endpoint, no auth required: {}", uri);
            }
        } catch (Exception e) {
            logger.error("Exception in JWT filter: {}", e.getMessage(), e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        logger.debug("✓ Proceeding to next filter");
        filterChain.doFilter(request, response);
    }
}