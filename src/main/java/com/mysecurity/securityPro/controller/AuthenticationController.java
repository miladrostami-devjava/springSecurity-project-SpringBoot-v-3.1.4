package com.mysecurity.securityPro.controller;


import com.mysecurity.securityPro.config.JWTUtils;
import com.mysecurity.securityPro.dao.UserDao;
import com.mysecurity.securityPro.dto.AuthenticationRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationManager authenticationManager;
   // private final UserDetailsService userDetailsService;
    private final UserDao userDao;
    private final JWTUtils jwtUtils;

    @PostMapping("/authenticate")
    public ResponseEntity<String> authenticate(
            @RequestBody AuthenticationRequest authenticationRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authenticationRequest.getEmail()
                        , authenticationRequest.getPassword())
        );
//        final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getEmail());
        final UserDetails userDetails = userDao.findUserByEmail(authenticationRequest.getEmail());

        if (userDetails != null) {
            return ResponseEntity.ok(jwtUtils.generateToken(userDetails));
        }
        return ResponseEntity.status(400).body("Some has error occurred");
    }





}
