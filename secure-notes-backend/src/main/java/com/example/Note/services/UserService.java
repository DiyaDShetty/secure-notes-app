package com.example.Note.services;

import com.example.Note.models.User;
import com.example.Note.payload.UserDTO;

import java.util.List;


public interface UserService {
    void updateUserRole(Long userId, String roleName);

    List<User> getAllUsers();

    UserDTO getUserById(Long id);

    User getUserByUsername(String username);
}
