package com.app.token.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping("/user")
    public String userPage(@AuthenticationPrincipal Jwt jwt) {
        Long accountId = jwt.getClaim("accountId");
        return String.format("%d :: 사용자 페이지입니다.", accountId);
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public String adminPage(@AuthenticationPrincipal Jwt jwt) {
        Long accountId = jwt.getClaim("accountId");
        return String.format("%d :: 관리자 페이지입니다.", accountId);
    }

}
