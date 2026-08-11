#ifndef CORE_H
#define CORE_H

#include <string>
#include <vector>
#include <memory>
#include <algorithm>
#include <cstdlib>

// ===========================================================
// SecurityLog
// ===========================================================
class SecurityLog {
private:
    static std::vector<std::string> logs;

public:
    static void addLog(const std::string& message) {
        logs.push_back(message);
    }

    static const std::vector<std::string>& getLogs() {
        return logs;
    }
};
inline std::vector<std::string> SecurityLog::logs;

// ===========================================================
// User (Base) + Admin / SecurityAnalyst (Derived)
// ===========================================================
class User {
protected:
    int userId;
    std::string username, password, email, role;

public:
    User(int id, std::string uname, std::string pass, std::string mail, std::string r)
        : userId(id), username(uname), password(pass), email(mail), role(r) {}

    virtual ~User() {}

    int getId() const { return userId; }
    std::string getUsername() const { return username; }
    std::string getEmail() const { return email; }
    std::string getRole() const { return role; }

    bool checkPassword(const std::string& pass) const { return password == pass; }

    std::string displayInfo() const {
        return "ID: " + std::to_string(userId) + " | Username: " + username +
               " | Email: " + email + " | Role: " + role;
    }

    virtual std::string permissionsText() const { return "General user permissions."; }
};

class Admin : public User {
public:
    Admin(int id, std::string uname, std::string pass, std::string mail)
        : User(id, uname, pass, mail, "Admin") {}

    std::string permissionsText() const override {
        return "Admin: Full access - User Management, Device Management, "
               "Attack Simulation, Firewall, Logs, Reports.";
    }
};

class SecurityAnalyst : public User {
public:
    SecurityAnalyst(int id, std::string uname, std::string pass, std::string mail)
        : User(id, uname, pass, mail, "Security Analyst") {}

    std::string permissionsText() const override {
        return "Security Analyst: Device Management, Attack Simulation, "
               "Firewall, Logs, Reports.";
    }
};

// ===========================================================
// OTPManager
// ===========================================================
class OTPManager {
private:
    int currentOTP = 0;

public:
    int generateOTP() {
        currentOTP = 100000 + rand() % 900000;
        return currentOTP;
    }
    bool checkOTP(int entered) const { return entered == currentOTP; }
};

// ===========================================================
// Authentication
// ===========================================================
class Authentication {
private:
    int failedAttempts = 0;

public:
    User* login(std::vector<std::shared_ptr<User>>& users,
                const std::string& uname, const std::string& pass) {
        for (auto& u : users) {
            if (u->getUsername() == uname) {
                if (u->checkPassword(pass)) {
                    SecurityLog::addLog("Login SUCCESS for user: " + uname);
                    return u.get();
                } else {
                    break;
                }
            }
        }
        failedAttempts++;
        SecurityLog::addLog("Login FAILED for username: " + uname);
        return nullptr;
    }

    int getFailedAttempts() const { return failedAttempts; }
};

// ===========================================================
// Device
// ===========================================================
class Device {
private:
    int deviceId;
    std::string name, type, ipAddress, status;

public:
    Device(int id, std::string n, std::string t, std::string ip, std::string st)
        : deviceId(id), name(n), type(t), ipAddress(ip), status(st) {}

    int getId() const { return deviceId; }
    std::string getStatus() const { return status; }
    void setStatus(const std::string& st) { status = st; }

    std::string displayInfo() const {
        return "Device ID: " + std::to_string(deviceId) + " | Name: " + name +
               " | Type: " + type + " | IP: " + ipAddress + " | Status: " + status;
    }
};

// ===========================================================
// CyberAttack (Base, abstract) + derived attack types
// Educational simulation ONLY - no real network activity.
// ===========================================================
class CyberAttack {
protected:
    std::string targetInfo;

public:
    CyberAttack(std::string target) : targetInfo(target) {}
    virtual ~CyberAttack() {}
    virtual std::string executeAttack() = 0;
    virtual std::string getName() const = 0;
};

class BruteForceAttack : public CyberAttack {
public:
    BruteForceAttack(std::string target) : CyberAttack(target) {}
    std::string getName() const override { return "Brute Force Attack"; }
    std::string executeAttack() override {
        SecurityLog::addLog("Simulated Brute Force Attack on: " + targetInfo);
        return "[SIMULATION] Brute Force Attack against '" + targetInfo +
               "'.\r\nTrying multiple simulated password combinations...\r\n"
               "Simulation complete. (No real system was targeted.)";
    }
};

class PhishingAttack : public CyberAttack {
public:
    PhishingAttack(std::string target) : CyberAttack(target) {}
    std::string getName() const override { return "Phishing Attack"; }
    std::string executeAttack() override {
        SecurityLog::addLog("Simulated Phishing Attack on: " + targetInfo);
        return "[SIMULATION] Phishing Attack against '" + targetInfo +
               "'.\r\nSending simulated fake email to test user awareness...\r\n"
               "Simulation complete. (No real email was sent.)";
    }
};

class DDoSAttack : public CyberAttack {
public:
    DDoSAttack(std::string target) : CyberAttack(target) {}
    std::string getName() const override { return "DDoS Attack"; }
    std::string executeAttack() override {
        SecurityLog::addLog("Simulated DDoS Attack on: " + targetInfo);
        return "[SIMULATION] DDoS Attack against '" + targetInfo +
               "'.\r\nFlooding simulated traffic requests (in-memory counters only)...\r\n"
               "Simulation complete. (No real server was flooded.)";
    }
};

// ===========================================================
// Firewall
// ===========================================================
class Firewall {
private:
    bool active = true;
    std::vector<std::string> rules;

public:
    Firewall() {
        rules.push_back("Block known malicious IP ranges");
        rules.push_back("Block repeated failed login attempts");
    }

    bool isActive() const { return active; }

    void toggleStatus() {
        active = !active;
        SecurityLog::addLog(std::string("Firewall status changed to ") + (active ? "ACTIVE" : "INACTIVE"));
    }

    const std::vector<std::string>& getRules() const { return rules; }

    void addRule(const std::string& rule) {
        rules.push_back(rule);
        SecurityLog::addLog("Firewall rule added: " + rule);
    }

    std::string inspectActivity(const std::string& activityDescription) {
        if (!active) {
            SecurityLog::addLog("Firewall INACTIVE - allowed activity: " + activityDescription);
            return "Firewall is INACTIVE. Activity allowed by default.";
        }
        bool suspicious = (rand() % 2 == 0);
        if (suspicious) {
            SecurityLog::addLog("Firewall BLOCKED suspicious activity: " + activityDescription);
            return "Decision: BLOCKED (activity flagged as suspicious).";
        } else {
            SecurityLog::addLog("Firewall ALLOWED activity: " + activityDescription);
            return "Decision: ALLOWED (activity looks normal).";
        }
    }
};

// ===========================================================
// Report
// ===========================================================
class Report {
public:
    static std::string generate(const std::vector<std::shared_ptr<User>>& users,
                                 const std::vector<Device>& devices,
                                 const std::vector<std::string>& attackHistory,
                                 const Firewall& firewall) {
        std::string out;
        out += "===================== SYSTEM REPORT =====================\r\n";

        out += "\r\n-- Users (" + std::to_string(users.size()) + ") --\r\n";
        for (auto& u : users) out += u->displayInfo() + "\r\n";

        out += "\r\n-- Devices (" + std::to_string(devices.size()) + ") --\r\n";
        if (devices.empty()) out += "No devices registered.\r\n";
        for (auto& d : devices) out += d.displayInfo() + "\r\n";

        out += "\r\n-- Attack Simulations Performed (" + std::to_string(attackHistory.size()) + ") --\r\n";
        if (attackHistory.empty()) out += "No attack simulations run yet.\r\n";
        for (auto& a : attackHistory) out += " - " + a + "\r\n";

        out += "\r\n-- Firewall --\r\n";
        out += std::string("Status: ") + (firewall.isActive() ? "ACTIVE" : "INACTIVE") + "\r\n";
        out += "Rules:\r\n";
        for (auto& r : firewall.getRules()) out += " - " + r + "\r\n";

        out += "\r\n-- Security Logs (" + std::to_string(SecurityLog::getLogs().size()) + ") --\r\n";
        for (auto& l : SecurityLog::getLogs()) out += " - " + l + "\r\n";

        out += "\r\n===========================================================\r\n";
        return out;
    }
};

#endif // CORE_H
