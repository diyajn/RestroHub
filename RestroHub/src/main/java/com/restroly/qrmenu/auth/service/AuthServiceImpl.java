package com.restroly.qrmenu.auth.service;

import com.restroly.qrmenu.auth.dto.*;
import com.restroly.qrmenu.common.exception.BusinessException;
import com.restroly.qrmenu.restaurant.dto.RestaurantRequestDTO;
import com.restroly.qrmenu.restaurant.dto.RestaurantResponseDTO;
import com.restroly.qrmenu.restaurant.service.RestaurantService;
import com.restroly.qrmenu.security.JwtTokenProvider;
import com.restroly.qrmenu.user.dto.UserRequest;
import com.restroly.qrmenu.user.dto.UserResponse;
import com.restroly.qrmenu.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;
    private final UserService userService;
    private final RestaurantService restaurantService;

    // ── LOGIN ──────────────────────────────────────────────────────────────────
    @Override
    public AuthResponse login(LoginRequest loginRequest) {
        log.info("Login attempt for user: {}", loginRequest.getUsername());

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String accessToken = jwtTokenProvider.generateAccessToken(userDetails);
            String refreshToken = jwtTokenProvider.generateRefreshToken(userDetails);

            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            log.info("User {} logged in successfully", loginRequest.getUsername());

            return AuthResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(jwtTokenProvider.getExpirationInSeconds())
                    .username(userDetails.getUsername())
                    .roles(roles)
                    .build();

        } catch (BadCredentialsException ex) {
            log.warn("Failed login attempt for user: {}", loginRequest.getUsername());
            throw new BadCredentialsException("Invalid username or password");
        } catch (AuthenticationException ex) {
            log.error("Authentication error for user {}: {}", loginRequest.getUsername(), ex.getMessage());
            throw new BusinessException("Authentication failed: " + ex.getMessage());
        }
    }

    // ── REGISTER ───────────────────────────────────────────────────────────────
    @Override
    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        log.info("Registration attempt for email: {}", request.getEmail());

        // Step 1: Create user with roles (UserServiceImpl handles role assignment)
        UserRequest userRequest = UserRequest.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(request.getPassword())
                .phone(request.getPhone())
                .roleIds(request.getRoleIds())
                .isActive(true)
                .build();

        UserResponse savedUser = userService.registerUser(userRequest);
        log.info("User registered successfully with ID: {}", savedUser.getId());

        // Step 2: Create restaurant if restaurant details are provided
        RestaurantResponseDTO savedRestaurant = null;
        if (StringUtils.hasText(request.getRestaurantName())) {
            log.info("Creating restaurant '{}' for user: {}", request.getRestaurantName(), request.getEmail());

            RestaurantRequestDTO restaurantRequest = RestaurantRequestDTO.builder()
                    .name(request.getRestaurantName())
                    .description(request.getRestaurantDescription())
                    .phoneNumber(request.getRestaurantPhone())
                    .isActive(true)
                    .build();

            savedRestaurant = restaurantService.createRestaurant(restaurantRequest);
            log.info("Restaurant created successfully with ID: {}", savedRestaurant.getRestId());
        }

        return RegisterResponse.builder()
                .user(savedUser)
                .restaurant(savedRestaurant)
                .message(savedRestaurant != null
                        ? "Registration successful. User and restaurant created."
                        : "Registration successful.")
                .build();
    }

    // ── REFRESH TOKEN ──────────────────────────────────────────────────────────
    @Override
    public AuthResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
        String refreshToken = refreshTokenRequest.getRefreshToken();
        log.debug("Refresh token request received");

        if (!jwtTokenProvider.validateToken(refreshToken)) {
            log.warn("Invalid or expired refresh token");
            throw new BusinessException("Invalid or expired refresh token");
        }

        if (!jwtTokenProvider.isRefreshToken(refreshToken)) {
            log.warn("Provided token is not a refresh token");
            throw new BusinessException("Token is not a refresh token");
        }

        String username = jwtTokenProvider.getUsernameFromToken(refreshToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        String newAccessToken = jwtTokenProvider.generateAccessToken(userDetails);
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        log.info("Token refreshed for user: {}", username);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getExpirationInSeconds())
                .username(username)
                .roles(roles)
                .build();
    }

    // ── LOGOUT ─────────────────────────────────────────────────────────────────
    @Override
    public void logout(String token) {
        // In a production system, you would typically:
        // 1. Add the token to a blacklist (Redis cache)
        // 2. Remove from any session store
        // For now, we just clear the security context
        SecurityContextHolder.clearContext();
        log.info("User logged out successfully");
    }
}