package com.example.Note.payload;

import com.example.Note.models.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
public class UserDTO {
    private Long userId;
    private String userName;
    private String email;
    private boolean accountNonLocked;
    private boolean accountNonExpired;
    private boolean credentialsNonExpired;
    private boolean enabled;
    private LocalDate credentialsExpiryDate;
    private LocalDate accountExpiryDate;
    private String twoFactorSecret;
    private boolean isTwoFactorEnabled;
    private String signUpMethod;
    private Role role;
    private LocalDateTime createdDate;
    private LocalDateTime updatedDate;

    public UserDTO(Long id, String firstName, String lastName, boolean isActive, boolean isVerified,
                   boolean isDeleted, boolean isLocked, LocalDate dateOfBirth, LocalDate joinDate,
                   String email, boolean emailVerified, String phoneNumber, Role role,
                   LocalDateTime createdAt, LocalDateTime updatedAt) {
    }
}