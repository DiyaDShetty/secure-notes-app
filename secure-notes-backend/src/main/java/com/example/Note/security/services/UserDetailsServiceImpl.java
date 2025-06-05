package com.example.Note.security.services;

import com.example.Note.models.User;
import com.example.Note.repositories.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    UserRepository userRepository;


    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));
            System.out.println("🔍 Loaded User: " + user.getUserName());
            System.out.println("🔍 Password: " + user.getPassword());
            System.out.println("🔍 Role: " + user.getRole().getRoleName());

            return UserDetailsImpl.build(user);
    }
}