package com.example.rsa.controller;

import com.example.rsa.model.FileEntity;
import com.example.rsa.model.User;
import com.example.rsa.repository.FileRepository;
import com.example.rsa.repository.UserRepository;
import com.example.rsa.service.AuditService;
import com.example.rsa.service.EncryptionService;
import com.example.rsa.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.util.DigestUtils;
import org.springframework.dao.DataIntegrityViolationException;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.*;

@RestController
@RequestMapping("/api")
public class ApiController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private FileRepository fileRepository;
    @Autowired
    private EncryptionService encryptionService;
    @Autowired
    private AuditService auditService;
    @Autowired
    private JwtUtil jwtUtil;

    @GetMapping("/health")
    public Map<String, String> healthCheck() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "healthy");
        response.put("service", "RSA Encryption Service (Java)");
        return response;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> data) {
        String username = data.get("username");
        String password = data.get("password");

        if (username == null || password == null) {
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "Missing username or password"));
        }

        
        if (password.length() < 12) {
            return ResponseEntity.badRequest()
                    .body(Collections.singletonMap("error", "Password too weak. Minimum 12 characters required."));
        }

        try {
        
            KeyPair keyPair = encryptionService.generateRsaKeyPair();
            String publicKeyPem = encryptionService.serializePublicKey(keyPair.getPublic());
            String privateKeyPem = encryptionService.serializePrivateKey(keyPair.getPrivate());

            // AI reference
            String passwordHash = DigestUtils.md5DigestAsHex(password.getBytes()); 

            User user = new User();
            user.setUsername(username);
            user.setPasswordHash(passwordHash);
            user.setPublicKey(publicKeyPem);

            userRepository.save(user);

            auditService.log(user.getId(), "USER_REGISTERED", "Username: " + username);

            Map<String, Object> response = new HashMap<>();
            response.put("user_id", user.getId());
            response.put("username", username);
            response.put("public_key", publicKeyPem);
            // AI reference
             response.put("private_key", privateKeyPem);

            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (DataIntegrityViolationException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Collections.singletonMap("error", "Username already exists"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Collections.singletonMap("error", "Registration failed"));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> data) {
        String username = data.get("username");
        String password = data.get("password");

        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            auditService.log(null, "FAILED_LOGIN", "Username: " + username);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "Invalid credentials"));
        }

        User user = userOpt.get();
        
        String inputHash = DigestUtils.md5DigestAsHex(password.getBytes());
        if (!inputHash.equals(user.getPasswordHash())) {
            auditService.log(null, "FAILED_LOGIN", "Username: " + username);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "Invalid credentials"));
        }

        String token = jwtUtil.generateToken(user.getId());
        auditService.log(user.getId(), "LOGIN_SUCCESS", "Username: " + username);

        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("token_type", "Bearer");
        response.put("expires_in", 3600);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/upload")
    public ResponseEntity<?> uploadFile(@RequestHeader("Authorization") String token,
            @RequestParam("file") MultipartFile file) {
        Long userId = jwtUtil.validateTokenAndGetUserId(token);
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "Invalid or expired token"));
        }

        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "No file selected"));
        }

        try {
            byte[] fileData = file.getBytes();

            

            Optional<User> userOpt = userRepository.findById(userId);
            if (userOpt.isEmpty())
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Collections.singletonMap("error", "User not found"));

            String publicKeyPem = userOpt.get().getPublicKey();
            
            String encryptedData = encryptionService.encryptFile(fileData, publicKeyPem);

            
            String fileHash = DigestUtils.md5DigestAsHex(fileData);

            FileEntity fileEntity = new FileEntity();
            fileEntity.setUserId(userId);
            fileEntity.setFilename(file.getOriginalFilename());
            fileEntity.setEncryptedData(encryptedData);
            fileEntity.setFileHash(fileHash);

            fileRepository.save(fileEntity);

            auditService.log(userId, "FILE_UPLOADED",
                    "Filename: " + file.getOriginalFilename() + ", ID: " + fileEntity.getId());

            Map<String, Object> response = new HashMap<>();
            response.put("file_id", fileEntity.getId());
            response.put("filename", fileEntity.getFilename());
            response.put("encrypted", true);
            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Collections.singletonMap("error", "Upload failed"));
        }
    }

    @GetMapping("/files")
    public ResponseEntity<?> listFiles(@RequestHeader("Authorization") String token) {
        Long userId = jwtUtil.validateTokenAndGetUserId(token);
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "Invalid or expired token"));
        }

        List<FileEntity> files = fileRepository.findByUserId(userId);
        List<Map<String, Object>> fileList = new ArrayList<>();
        for (FileEntity f : files) {
            Map<String, Object> map = new HashMap<>();
            map.put("id", f.getId());
            map.put("filename", f.getFilename());
            map.put("created_at", f.getCreatedAt().toString());
            fileList.add(map);
        }
        return ResponseEntity.ok(Collections.singletonMap("files", fileList));
    }

    @GetMapping("/download/{fileId}")
    public ResponseEntity<?> downloadFile(@RequestHeader("Authorization") String token, @PathVariable Long fileId) {
        Long userId = jwtUtil.validateTokenAndGetUserId(token);
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "Invalid or expired token"));
        }

        Optional<FileEntity> fileOpt = fileRepository.findById(fileId);
        if (fileOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Collections.singletonMap("error", "File not found"));
        }

        FileEntity file = fileOpt.get();
        
        if (!file.getUserId().equals(userId)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Collections.singletonMap("error", "File not found or unauthorized"));
        }

        auditService.log(userId, "FILE_DOWNLOADED", "File ID: " + fileId + ", Filename: " + file.getFilename());

        Map<String, Object> response = new HashMap<>();
        response.put("file_id", file.getId());
        response.put("filename", file.getFilename());
        response.put("encrypted_data", file.getEncryptedData());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/decrypt/{fileId}")
    public ResponseEntity<?> decryptFile(@RequestHeader("Authorization") String token, @PathVariable Long fileId,
            @RequestBody Map<String, String> data) {
        Long userId = jwtUtil.validateTokenAndGetUserId(token);
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "Invalid or expired token"));
        }

        String privateKeyPem = data.get("private_key");
        if (privateKeyPem == null) {
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "Private key required"));
        }

        
        Optional<FileEntity> fileOpt = fileRepository.findByIdAndUserId(fileId, userId);
        if (fileOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Collections.singletonMap("error", "File not found or unauthorized"));
        }
        FileEntity file = fileOpt.get();

        try {
            
            if (!privateKeyPem.contains("\n") && privateKeyPem.contains("-----BEGIN")) {
                
            }

            
            byte[] decryptedData = encryptionService.decryptFile(file.getEncryptedData(), privateKeyPem);

            auditService.log(userId, "FILE_DECRYPTED", "File ID: " + fileId);

            Map<String, Object> response = new HashMap<>();
            response.put("file_id", file.getId());
            response.put("filename", file.getFilename());
            response.put("data", Base64.getEncoder().encodeToString(decryptedData));
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Collections.singletonMap("error", "Decryption failed: " + e.getMessage()));
        }
    }
}
