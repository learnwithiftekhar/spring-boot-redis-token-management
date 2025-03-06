package com.example.redissessionmanagement.controller;

import com.example.redissessionmanagement.dto.JwtResponse;
import com.example.redissessionmanagement.dto.LoginRequest;
import com.example.redissessionmanagement.dto.RefreshTokenRequest;
import com.example.redissessionmanagement.security.JwtTokenProvider;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;

    public AuthController(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider, UserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        // Authenticate the user
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        // Set authentication in security context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generate JWT token
        String jwt = jwtTokenProvider.generateToken(authentication);

        // generate refresh token
        String refreshToken = jwtTokenProvider.generateRefreshToken(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        return ResponseEntity.ok(
                new JwtResponse(
                        jwt,
                        refreshToken,
                        userDetails.getUsername(),
                        userDetails.getAuthorities()
                )
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        // Validate the refresh token
        if(!jwtTokenProvider.validateToken(request.getRefreshToken())) {
            return ResponseEntity.badRequest()
                    .body("Invalid refresh token");
        }

        // Extract the username from refresh token
        String username = jwtTokenProvider.getUsernameFromToken(request.getRefreshToken());

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // Create new authentication object
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());


        String newAccessToken = jwtTokenProvider.generateToken(authToken);
        return ResponseEntity.ok(new JwtResponse(
                newAccessToken,
                request.getRefreshToken(),
                username,
                userDetails.getAuthorities()
        ));
    }
}
