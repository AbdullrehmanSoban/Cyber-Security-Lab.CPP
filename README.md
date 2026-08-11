# Cyber Security Simulation System

A Windows desktop GUI application built with **native Win32 API (C++)** that simulates a basic cyber-security operations dashboard — user management, device management, attack simulations, firewall controls, security logging, and reporting. This is an **educational simulation only**; it does not perform any real network activity.

## Features

- **Login + Two-Factor Authentication (OTP)** — role-based login (Admin / Security Analyst), followed by a demo OTP verification step.
- **User Management** *(Admin only)* — add/remove system users and assign roles.
- **Device Management** — register devices and update their status (Online / Offline / Quarantined).
- **Attack Simulation** — run simulated Brute Force, Phishing, and DDoS attacks against a chosen target (all in-memory, no real traffic).
- **Firewall** — toggle firewall status, add custom rules, and inspect simulated suspicious activity.
- **Security Logs** — a running log of every action taken in the system.
- **Reports** — generate a full text summary of users, devices, attack history, firewall status, and logs.

## Tech Stack

- C++ (C++11 compatible)
- Native Win32 API for the GUI (no external libraries beyond the standard Windows `comctl32` common controls)

## Project Structure

```
├── main.cpp    # GUI code — window, controls, event handling
├── core.h      # Core business logic (User, Admin, Device, Firewall, etc.)
└── Project1.dev  # Dev-C++ project file
```

## Getting Started

### Requirements
- [Dev-C++](https://www.bloodshed.net/) (or any MinGW-based C++ compiler)

### Build & Run (Dev-C++)
1. Clone this repository.
2. Open `Project1.dev` in Dev-C++.
3. Go to **Project → Project Options → Parameters → Linker**, and make sure `-lcomctl32` is listed.
4. Press **F11** (Compile & Run).

### Build & Run (command line, MinGW)
```bash
g++ main.cpp -o CyberSecuritySim.exe -mwindows -lcomctl32 -std=c++11
```

## Default Logins

| Username | Password    | Role              |
|----------|-------------|-------------------|
| admin    | admin123    | Admin             |
| analyst  | analyst123  | Security Analyst  |

> ⚠️ These are demo credentials for local testing only — no real authentication or persistence is used. All data (users, devices, logs) resets when the app closes, since everything is stored in memory.

## Disclaimer

This project is for **educational purposes only**. It does not send real phishing emails, perform real brute-force attacks, or generate real network traffic. All "attacks" and "firewall inspections" are simulated in-memory with no external effect.

## License

Feel free to use and modify this project for learning purposes.
