# 🛡️ VulnVault

**AI-Powered Vulnerability Management & Pentest Reporting Platform**

VulnVault is an internal security tool for managing penetration testing workflows — from vulnerability discovery to report generation. Built with Google Gemini AI for automated bilingual report writing (EN/ID).

---

## ✨ Features

### 🤖 AI-Powered Reporting
- **AI Report Generator** — Provide basic vulnerability details, Gemini crafts a professional bilingual report (English + Bahasa Indonesia)
- **Ask AI** — Upload screenshots from security tools (Burp Suite, Shodan, etc.) and let AI identify the vulnerability
- **Multi-model support** — Choose from Gemini 3.1 Pro, 3 Flash, 2.5 Pro/Flash, and legacy models

### 👥 Multi-Role Access Control
| Role | Access |
|------|--------|
| **Admin** | Full access — user management, all projects, all data |
| **Manager** | Project management, user creation, access request approval |
| **PM** | Same as Manager — project oversight and engineer assignment |
| **Engineer** | Vulnerability library, AI tools, assigned projects only |

### 📁 Project Management
- **Client & Project hierarchy** — Organize pentest engagements by client
- **PIC & Assist assignment** — Assign primary and secondary engineers per project
- **Deadline tracking** — Kickoff, initial report, and final report dates with visual timeline
- **Report status tracking** — Initial and Final report phase completion badges
- **Report link management** — Attach English and Indonesian report URLs

### 📊 Management Portal
- **Dashboard** — KPI overview with client-grouped deadline timeline
- **Activity Log** — Full audit trail for user, CRUD, and project request actions
- **User Management** — Create users, reset passwords, delete with cascade cleanup
- **Access Requests** — Engineers request project access; PM/Manager approve or reject

### 🔒 Security
- HMAC-signed session cookies with timing-safe comparison
- Bcrypt password hashing (10 rounds)
- Role-based API middleware on all endpoints
- XSS-safe HTML report generation
- Parameterized SQL queries throughout

---

## 🚀 Quick Start

### Prerequisites
- **Node.js** ≥ 18.0.0
- **Google AI Studio API Key** — [Get one free](https://aistudio.google.com/app/apikey)

### Installation

```bash
# Clone the repository
git clone https://github.com/VIN028/VulnVault.git
cd VulnVault

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env and set your SESSION_SECRET (min 16 random chars)

# Start the server
node server.js
```

Open `http://localhost:3000` in your browser.

### Default Accounts

| Username | Password | Role |
|----------|----------|------|
| `admin` | `Cisometric123@` | Admin |
| `manager` | `Cisometric123@` | Manager |
| `pm` | `Cisometric123@` | PM |

> ⚠️ **Change the default passwords** immediately after first login via the User Management section.

---

## 🏗️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Node.js + Express |
| **Database** | SQLite3 |
| **Auth** | HMAC cookies + bcryptjs |
| **AI** | Google Gemini API (`@google/generative-ai`) |
| **Upload** | Multer (image uploads) |
| **Frontend** | Vanilla HTML/CSS/JS (dark theme) |

---

## 📁 Project Structure

```
VulnVault/
├── server.js          # Express API server (all routes)
├── database.js        # SQLite schema, queries, and data access
├── auth.js            # Authentication middleware (HMAC sessions)
├── package.json
├── .env.example       # Environment template
├── public/
│   ├── index.html     # Engineer app (library, AI generator, ask AI)
│   ├── portal.html    # Management portal (dashboard, users, projects)
│   ├── login.html     # Login page
│   ├── css/style.css  # Design system
│   └── js/app.js      # Frontend logic
└── uploads/           # POC screenshots (gitignored)
```

---

## 🔑 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `3000` |
| `SESSION_SECRET` | HMAC signing key for cookies | *(required)* |

> The Gemini API key is stored in the user's browser (`localStorage`) and sent per-request — never stored on the server.

---

## 📸 Screenshots

The app features a modern dark theme with:
- Glassmorphism sidebar navigation
- Client-grouped deadline timeline with status badges
- Bilingual (EN/ID) toggle on generated reports
- Multi-image POC upload with drag, click, or Ctrl+V paste

---

## 📄 License

Private — Internal use only.
