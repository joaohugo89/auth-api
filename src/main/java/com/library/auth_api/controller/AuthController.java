package com.library.auth_api.controller;

import com.library.auth_api.dto.request.LoginRequest;
import com.library.auth_api.dto.request.SignupRequest;
import com.library.auth_api.dto.request.TokenRefreshRequest;
import com.library.auth_api.dto.response.JwtResponse;
import com.library.auth_api.dto.response.MessageResponse;
import com.library.auth_api.dto.response.TokenRefreshResponse;
import com.library.auth_api.exception.TokenRefreshException;
import com.library.auth_api.model.ERole;
import com.library.auth_api.model.RefreshToken;
import com.library.auth_api.model.Role;
import com.library.auth_api.model.User;
import com.library.auth_api.repositories.RoleRepository;
import com.library.auth_api.repositories.UserRepository;
import com.library.auth_api.security.UserDetailsImpl;
import com.library.auth_api.security.UserDetailsServiceImpl;
import com.library.auth_api.service.JwtService;
import com.library.auth_api.service.RefreshTokenService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtService jwtService;

    @Autowired
    RefreshTokenService refreshTokenService;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin-only")
    public String onlyForAdmins() {
        return "Hello Admin!";
    }

    @PreAuthorize("hasRole('ROLE_MODERATOR')")
    @GetMapping("/mod-only")
    public String onlyForModerators() {
        return "Hello Moderator!";
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping("/user-only")
    public String onlyForUsers() {
        return "Hello User!";
    }

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> checkStatus(HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();

        // Verifica se está autenticado (access token válido)
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean hasAccessToken = authentication != null &&
                authentication.isAuthenticated() &&
                !(authentication instanceof AnonymousAuthenticationToken);

        // Verifica se há refresh_token nos cookies
        boolean hasRefreshToken = false;
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("refresh_token".equals(cookie.getName())) {
                    hasRefreshToken = true;
                    break;
                }
            }
        }

        response.put("hasAccessToken", hasAccessToken);
        response.put("hasRefreshToken", hasRefreshToken);

        return ResponseEntity.ok(response); // sempre 200
    }


    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtService.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        refreshTokenService.deleteByUserId(userDetails.getId());

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", jwt)
            .httpOnly(true)
            .secure(true) // ⚠️ set to false in local development if not using HTTPS
            .path("/")
            .maxAge(15 * 60) // 15 minutes
            .sameSite("None")
            .build();

        ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", refreshToken.getToken())
            .httpOnly(true)
            .secure(true)  // Ensure cookie is sent only over HTTPS
            .path("/")  // Set path for cookie validity
            .maxAge(86400)  // Set expiration for 1 day
            .sameSite("None")
            .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        return ResponseEntity.ok()
            .body(new JwtResponse(jwt,
                refreshToken.getToken(),
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshToken(
            @RequestBody(required = false) TokenRefreshRequest request,
            @CookieValue(value = "refresh_token", defaultValue = "") String refreshTokenFromCookie,
            HttpServletResponse response) {
        if (refreshTokenFromCookie.isEmpty()) {
            throw new TokenRefreshException("No refresh token found in cookie", "Refresh token is missing in cookie!");
        }

        return refreshTokenService.findByToken(refreshTokenFromCookie)
                .map(refreshToken -> refreshTokenService.verifyExpiration(refreshToken))
                .map(RefreshToken::getUser)
                .map(user -> {
                    UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(user.getUsername());
                    Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    String newAccessToken = jwtService.generateJwtToken(authentication);

                    // Create new access_token cookie
                    ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", newAccessToken)
                            .httpOnly(true)
                            .secure(true) // ⚠️ set to false in local development if not using HTTPS
                            .path("/")
                            .maxAge(15 * 60) // 15 minutes
                            .sameSite("None")
                            .build();

                    // Add the new access_token cookie to the response
                    response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());

                    return ResponseEntity.ok(new TokenRefreshResponse(newAccessToken, refreshTokenFromCookie));
                })
                .orElseThrow(() -> new TokenRefreshException(
                        request != null ? request.getRefreshToken() : null,
                        "Refresh token is not valid or expired!"));
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser(HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            logger.error("Authentication is null");
            return ResponseEntity.badRequest().body(new MessageResponse("Error: User is not authenticated!"));
        }

        Object principal = authentication.getPrincipal();
        logger.info("Principal class: {}", principal.getClass().getName());

        if (!(principal instanceof UserDetailsImpl userDetails)) {
            logger.error("Principal is not an instance of UserDetailsImpl");
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Invalid user principal!"));
        }

        Long userId = userDetails.getId();
        refreshTokenService.deleteByUserId(userId);

            // 🧹 Clear access and refresh token cookies
        ResponseCookie clearAccessToken = ResponseCookie.from("access_token", "")
            .path("/")
            .httpOnly(true)
            .secure(true) // Ensure cookie is sent only over HTTPS
            .sameSite("Lax")
            .maxAge(0) // Expire now
            .build();

        ResponseCookie clearRefreshToken = ResponseCookie.from("refresh_token", "")
            .path("/")
            .httpOnly(true)
            .secure(true) // Ensure cookie is sent only over HTTPS
            .sameSite("Lax")
            .maxAge(0)
            .build();

        response.addHeader(HttpHeaders.SET_COOKIE, clearAccessToken.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, clearRefreshToken.toString());
        return ResponseEntity.ok(new MessageResponse("Log out successful!"));
    }
}
