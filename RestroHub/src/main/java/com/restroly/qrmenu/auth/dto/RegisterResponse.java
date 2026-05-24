package com.restroly.qrmenu.auth.dto;

import com.restroly.qrmenu.restaurant.dto.RestaurantResponseDTO;
import com.restroly.qrmenu.user.dto.UserResponse;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Registration response")
public class RegisterResponse {

    @Schema(description = "Registered user details")
    private UserResponse user;

    @Schema(description = "Created restaurant details (null if no restaurant was created)")
    private RestaurantResponseDTO restaurant;

    @Schema(description = "Success message")
    private String message;
}