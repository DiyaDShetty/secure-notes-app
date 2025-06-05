# 🛡️ Secure Notes Backend

A secure note-taking REST API built using **Spring Boot**, **JWT authentication**, and **role-based authorization**. This backend supports user registration, login, note management, and admin capabilities.


---

## ⚙️ Technologies Used

- Java 17+
- Spring Boot
- Spring Security (JWT)
- Spring Data JPA (Hibernate)
- MySQL / H2
- Maven

---

## 🚀 Features

- 📝 Create, update, delete notes (for authenticated users)
- 🔐 JWT-based login system
- 👥 Role-based access (`ROLE_USER`, `ROLE_ADMIN`)
- 🔄 Admin can manage users and roles
- 🌐 CSRF token support for frontend integration

---

## ✅ Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/secure-notes-backend.git
cd secure-notes-backend
