# PhoneBook-Manager

A FastAPI-based PhoneBook application that allows users to securely store, retrieve, and manage contact information with role-based access control (read/write).

---

## Features
- Add new contacts with **write access**.
- Retrieve contact information with **read access**.
- Authentication and authorization using `OAuth2` with `Bearer` tokens.
- Input validation using regular expressions.
- Database integration with **SQLite** for contact storage.
- Dockerized for easy deployment.

---

## Prerequisites
1. Install [Docker](https://www.docker.com/get-started).
2. Install [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) (optional, but recommended for source code management).

---

## Installation and Running the Application
Follow these steps to build and run the project:

### 1. Clone the Repository
```bash
git clone <repository_url>
cd PhoneBook_Starter
```

### 2. Build and Run Using Docker Compose

### 3. Run Unit Tests:
The application will start and can be accessed at:

- Base URL: http://localhost:8000
- Interactive API Docs: http://localhost:8000/docs
