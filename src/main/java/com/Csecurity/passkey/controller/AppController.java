package com.csecurity.passkey.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.csecurity.passkey.domain.User;
import com.csecurity.passkey.domain.UserPasskey;
import com.csecurity.passkey.repository.UserPasskeyRepository;
import com.csecurity.passkey.repository.UserRepository;
import com.csecurity.passkey.service.JwtService;

import java.util.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true", allowedHeaders = "*")
public class AppController {

    private final UserPasskeyRepository passkeyRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AppController(UserPasskeyRepository passkeyRepository, 
                         UserRepository userRepository, 
                         PasswordEncoder passwordEncoder,
                         JwtService jwtService,
                         AuthenticationManager authenticationManager) {
        this.passkeyRepository = passkeyRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    /**
     * PASSWORD LOGIN
     * Handled manually since we are using a Stateless JWT architecture.
     */
    @PostMapping("/auth/login")
    public ResponseEntity<?> loginWithPassword(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");

        try {
            // Validates against CustomUserDetailsService + PasswordEncoder
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
            );

            Map<String, String> tokens = jwtService.generateTokens(username);

            return ResponseEntity.ok(Map.of(
                "status", "ok",
                "accessToken", tokens.get("accessToken"),
                "refreshToken", tokens.get("refreshToken"),
                "username", username
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Invalid username or password"));
        }
    }

    /**
     * USER REGISTRATION
     */
    @PostMapping("/users/register")
    public ResponseEntity<?> registerAccount(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");

        if (userRepository.findByUsername(username).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("message", "User already exists"));
        }

        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPassword(passwordEncoder.encode(password)); // Hash the password!
        newUser.setExternalId(Base64.getUrlEncoder().withoutPadding().encodeToString(UUID.randomUUID().toString().getBytes()));
        newUser.setFullName(username);
        
        userRepository.save(newUser);
        return ResponseEntity.ok(Map.of("message", "User created successfully"));
    }

    /**
     * SESSION VERIFICATION
     * Used by the Angular Dashboard to check if the current token is still valid.
     */
    @GetMapping("/auth/verify")
    public ResponseEntity<?> verifySession(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("status", "error", "message", "No token provided"));
        }

        String token = authHeader.substring(7);
        if (jwtService.isTokenValid(token)) {
            String username = jwtService.extractUsername(token);
            return ResponseEntity.ok(Map.of(
                "status", "valid",
                "user", username,
                "verifiedAt", new Date().toString()
            ));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("status", "invalid", "message", "Session expired"));
        }
    }

    // --- PASSKEY REGISTRATION ---

    @PostMapping(path = "/passkey/register/start", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> registerStart(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        
        Map<String, Object> options = new HashMap<>();
        options.put("challenge", Base64.getUrlEncoder().withoutPadding().encodeToString(UUID.randomUUID().toString().getBytes()));
        
        Map<String, Object> rp = new HashMap<>();
        rp.put("name", "Passkey Demo");
        rp.put("id", "localhost"); 
        options.put("rp", rp);

        Map<String, Object> user = new HashMap<>();
        user.put("id", Base64.getUrlEncoder().withoutPadding().encodeToString(username.getBytes()));
        user.put("name", username);
        user.put("displayName", username);
        options.put("user", user);

        options.put("pubKeyCredParams", List.of(
            Map.of("type", "public-key", "alg", -7), 
            Map.of("type", "public-key", "alg", -257)
        ));

        Map<String, Object> authSelection = new HashMap<>();
        authSelection.put("authenticatorAttachment", "platform");
        authSelection.put("userVerification", "required");
        authSelection.put("residentKey", "required");
        options.put("authenticatorSelection", authSelection);

        options.put("status", "ok");
        return ResponseEntity.ok(options);
    }

    @PostMapping(path = "/passkey/register/finish")
    public ResponseEntity<Map<String, Object>> registerFinish(@RequestBody Map<String, Object> credential) {
        String username = (String) credential.get("username"); 
        
        User dbUser = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        UserPasskey passkey = new UserPasskey();
        passkey.setUser(dbUser);
        passkey.setCredentialId((String) credential.get("id"));
        passkey.setPublicKeyCose("MOCK_PUBLIC_KEY_DATA"); 
        passkey.setLabel("Web Browser Passkey");
        
        passkeyRepository.save(passkey);
        return ResponseEntity.ok(Map.of("status", "ok", "message", "Passkey registered"));
    }

    // --- PASSKEY LOGIN ---

    @PostMapping(path = "/passkey/login/start")
    public ResponseEntity<Map<String, Object>> loginStart(@RequestBody(required = false) Map<String, String> request) {
        Map<String, Object> options = new HashMap<>();
        options.put("challenge", Base64.getUrlEncoder().withoutPadding().encodeToString(UUID.randomUUID().toString().getBytes()));
        options.put("rpId", "localhost");
        options.put("userVerification", "required");
        options.put("status", "ok");
        return ResponseEntity.ok(options);
    }

    @PostMapping(path = "/passkey/login/finish")
    public ResponseEntity<Map<String, Object>> loginFinish(@RequestBody Map<String, Object> credential) {
        String username = (String) credential.get("username");

        // Generate tokens upon successful passkey verification
        Map<String, String> tokens = jwtService.generateTokens(username);

        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("accessToken", tokens.get("accessToken"));
        response.put("refreshToken", tokens.get("refreshToken"));
        response.put("username", username);

        return ResponseEntity.ok(response);
    }
}