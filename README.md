# RSA-Based File Encryption Service - Secure SDLC Case Study


## Overview

This repository demonstrates a comprehensive implementation of Secure Software Development Lifecycle (SSDLC) principles through an RSA-based file encryption service. The project serves as showcasing security requirements engineering, threat modeling, secure architecture design, and comprehensive security testing throughout all phases of the development lifecycle.

The implementation features RSA asymmetric encryption,RESTful API design, and includes intentional security vulnerabilities with corresponding detection tests to demonstrate effective security testing methodologies.

---

## Quick Start (Two-Terminal Setup)

### Terminal 1: Server Side

Start the Spring Boot application:

```bash
# Navigate to project root
cd /path/to/rsa-based-encryption-master

# Build the project (first time only)
mvn clean install

# Run the Spring Boot server
mvn spring-boot:run
```

**Output**:
```
Server running on: http://localhost:5000
```

The server is now ready to accept requests. Keep this terminal open.

---

### Terminal 2: Client Side

In a new terminal, run the Python CLI client:

```bash
# Navigate to client directory
cd /path/to/rsa-based-encryption-master/RSA-JavaSpringboot

# Run the Python client
python3 client.py
```


---

