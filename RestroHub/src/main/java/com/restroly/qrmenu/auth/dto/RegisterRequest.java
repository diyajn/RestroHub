package com.restroly.qrmenu.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.*;

import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "User registration request payload")
public class RegisterRequest {

    @NotBlank(message = "First name is required")
    @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
    @Schema(description = "First name", example = "John")
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
    @Schema(description = "Last name", example = "Doe")
    private String lastName;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Schema(description = "Email address", example = "john@example.com")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters")
    @Pattern(
            regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{8,}$",
            message = "Password must contain at least one digit, one lowercase, one uppercase, one special character and no whitespace"
    )
    @Schema(description = "Password", example = "Admin@1234")
    private String password;

    @Pattern(regexp = "^[0-9]{10}$", message = "Phone number must be 10 digits")
    @Schema(description = "Phone number", example = "9876543210")
    private String phone;

    @Schema(description = "Role IDs to assign during registration", example = "[1, 2]")
    private Set<Long> roleIds;

    // ── Restaurant fields (optional — only for Restaurant Admins) ──

    @Schema(description = "Restaurant name (optional, for restaurant owners)", example = "Johns Kitchen")
    private String restaurantName;

    @Schema(description = "Restaurant description", example = "Best food in town")
    private String restaurantDescription;

    @Pattern(regexp = "^[0-9]{10}$", message = "Restaurant phone number must be 10 digits")
    @Schema(description = "Restaurant phone number", example = "9876543211")
    private String restaurantPhone;
}
