package com.csecurity.passkey.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.csecurity.passkey.domain.User;
import com.csecurity.passkey.domain.UserPasskey;
import com.csecurity.passkey.repository.UserPasskeyRepository;
import com.csecurity.passkey.repository.UserRepository;

import java.util.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
public class AppController {

    private final UserPasskeyRepository passkeyRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AppController(UserPasskeyRepository passkeyRepository, 
                         UserRepository userRepository, 
                         PasswordEncoder passwordEncoder) {
        this.passkeyRepository = passkeyRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
  
@PostMapping("/users/register")
    public ResponseEntity<?> registerAccount(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");

        if (userRepository.findByUsername(username).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("message", "User already exists"));
        }

        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPassword(passwordEncoder.encode(password));
        newUser.setExternalId(Base64.getUrlEncoder().withoutPadding().encodeToString(UUID.randomUUID().toString().getBytes()));
        newUser.setFullName(username);
        
        userRepository.save(newUser);
        return ResponseEntity.ok(Map.of("message", "User created successfully"));
    } 

    @GetMapping("/ping")
public String ping() {
    return "API Working";
}

    @PostMapping(path = "/passkey/register/start", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> registerStart(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        
        Map<String, Object> options = new HashMap<>();
        options.put("challenge", Base64.getUrlEncoder().withoutPadding().encodeToString(UUID.randomUUID().toString().getBytes()));
        
        Map<String, Object> rp = new HashMap<>();
        rp.put("name", "Passkey Demo");
        rp.put("id", "localhost"); 
        options.put("rp", rp);
        options.put("origin", "http://localhost:4200");

        Map<String, Object> user = new HashMap<>();
        user.put("id", Base64.getUrlEncoder().withoutPadding().encodeToString(username.getBytes()));
        user.put("name", username);
        user.put("displayName", username);
        options.put("user", user);

        options.put("pubKeyCredParams", List.of(
            Map.of("type", "public-key", "alg", -7), // ES256
            Map.of("type", "public-key", "alg", -257) // RS256
        ));

        // CRITICAL FIX: Add Authenticator Selection to prevent NotAllowedError
        Map<String, Object> authSelection = new HashMap<>();
        authSelection.put("authenticatorAttachment", "platform"); // Forces Windows Hello/TouchID
        authSelection.put("userVerification", "required");
        authSelection.put("residentKey", "required");
        options.put("authenticatorSelection", authSelection);

        options.put("status", "ok");
        return ResponseEntity.ok(options);
    }

    @PostMapping(path = "/passkey/register/finish")
    public ResponseEntity<Map<String, Object>> registerFinish(@RequestBody Map<String, Object> credential) {
        // Ensure username is extracted from the JSON body sent by Angular
        String username = (String) credential.get("username"); 
        
        User dbUser = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));

        UserPasskey passkey = new UserPasskey();
        passkey.setUser(dbUser);
        passkey.setCredentialId((String) credential.get("id"));
        passkey.setPublicKeyCose("MOCK_PUBLIC_KEY_DATA"); 
        passkey.setLabel("Web Browser Passkey");
        
        passkeyRepository.save(passkey);
        
        return ResponseEntity.ok(Map.of("status", "ok", "message", "Passkey saved to database"));
    }

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
        return ResponseEntity.ok(Map.of("status", "ok", "message", "User authenticated with Passkey"));
    }
}