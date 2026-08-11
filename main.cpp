// CyberSecuritySim - Win32 native GUI version
// Compiles with plain MinGW (the compiler bundled with Dev-C++).
// No Qt / no external libraries required.
//
// In Dev-C++: File -> New -> Project -> Windows Application (or Empty Project),
// add this file + core.h, then Execute -> Compile & Run.
// If using a plain "Console/Empty" project, make sure the project type is set
// to a Windows GUI application (Project Options -> uncheck "Console Application"),
// or compile from a terminal with:
//   g++ main.cpp -o CyberSecuritySim.exe -mwindows -lcomctl32

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <memory>
#include <ctime>
#include <cstdlib>
#include "core.h"

#pragma comment(lib, "comctl32.lib")

// -----------------------------------------------------------
// Control IDs
// -----------------------------------------------------------
enum {
    // Login
    ID_LOGIN_USER = 100, ID_LOGIN_PASS, ID_LOGIN_BTN, ID_LOGIN_STATUS,
    // OTP
    ID_OTP_DISPLAY = 200, ID_OTP_INPUT, ID_OTP_BTN, ID_OTP_STATUS,
    // Sidebar (dashboard nav)
    ID_NAV_USERS = 300, ID_NAV_DEVICES, ID_NAV_ATTACKS, ID_NAV_FIREWALL,
    ID_NAV_LOGS, ID_NAV_REPORT, ID_NAV_LOGOUT, ID_WELCOME_LABEL,
    // Users panel
    ID_USER_LIST = 400, ID_USER_NAME, ID_USER_PASS, ID_USER_EMAIL,
    ID_USER_ROLE_COMBO, ID_USER_ADD_BTN, ID_USER_REMOVE_ID, ID_USER_REMOVE_BTN,
    // Devices panel
    ID_DEV_LIST = 500, ID_DEV_NAME, ID_DEV_TYPE, ID_DEV_IP, ID_DEV_ADD_BTN,
    ID_DEV_STATUS_ID, ID_DEV_STATUS_COMBO, ID_DEV_STATUS_BTN,
    // Attacks panel
    ID_ATK_TYPE_COMBO = 600, ID_ATK_TARGET, ID_ATK_RUN_BTN, ID_ATK_OUTPUT,
    // Firewall panel
    ID_FW_STATUS_LABEL = 700, ID_FW_TOGGLE_BTN, ID_FW_RULES_LIST,
    ID_FW_NEW_RULE, ID_FW_ADD_RULE_BTN, ID_FW_ACTIVITY, ID_FW_INSPECT_BTN, ID_FW_OUTPUT,
    // Logs panel
    ID_LOGS_LIST = 800, ID_LOGS_REFRESH_BTN,
    // Report panel
    ID_REPORT_BTN = 900, ID_REPORT_OUTPUT
};

// -----------------------------------------------------------
// Application state
// -----------------------------------------------------------
enum AppState { STATE_LOGIN, STATE_OTP, STATE_DASHBOARD };
enum DashPanel { PANEL_USERS, PANEL_DEVICES, PANEL_ATTACKS, PANEL_FIREWALL, PANEL_LOGS, PANEL_REPORT };

static AppState g_state = STATE_LOGIN;
static DashPanel g_panel = PANEL_USERS;

static std::vector<std::shared_ptr<User>> g_users;
static std::vector<Device> g_devices;
static std::vector<std::string> g_attackHistory;
static Firewall g_firewall;
static Authentication g_auth;
static OTPManager g_otp;
static int g_nextUserId = 1, g_nextDeviceId = 1;
static User* g_currentUser = nullptr;

static HWND g_hMain;
static HFONT g_hFont;

// Control handle groups, so we can show/hide by panel
static std::vector<HWND> g_loginControls, g_otpControls, g_sidebarControls;
static std::vector<HWND> g_usersControls, g_devicesControls, g_attacksControls,
                          g_firewallControls, g_logsControls, g_reportControls;

// -----------------------------------------------------------
// Helpers
// -----------------------------------------------------------
static HWND MakeCtl(LPCSTR cls, LPCSTR text, DWORD style, int x, int y, int w, int hgt,
                     HWND parent, int id, std::vector<HWND>* group = nullptr) {
    HWND ctl = CreateWindowExA(0, cls, text, style, x, y, w, hgt, parent,
                                (HMENU)(INT_PTR)id, GetModuleHandle(nullptr), nullptr);
    SendMessageA(ctl, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    if (group) group->push_back(ctl);
    return ctl;
}

static void SetTxt(HWND h, const std::string& s) { SetWindowTextA(h, s.c_str()); }
static std::string GetTxt(HWND h) {
    char buf[2048];
    GetWindowTextA(h, buf, sizeof(buf));
    return std::string(buf);
}

static void HideGroup(std::vector<HWND>& g) { for (auto h : g) ShowWindow(h, SW_HIDE); }
static void ShowGroup(std::vector<HWND>& g) { for (auto h : g) ShowWindow(h, SW_SHOW); }

static void RefreshUserList();
static void RefreshDeviceList();
static void RefreshFirewallView();
static void RefreshLogsList();
static void UpdateView();

// -----------------------------------------------------------
// Action handlers
// -----------------------------------------------------------
static void DoLogin() {
    std::string uname = GetTxt(GetDlgItem(g_hMain, ID_LOGIN_USER));
    std::string pass = GetTxt(GetDlgItem(g_hMain, ID_LOGIN_PASS));

    User* u = g_auth.login(g_users, uname, pass);
    if (!u) {
        SetTxt(GetDlgItem(g_hMain, ID_LOGIN_STATUS),
               "Invalid username or password. (Failed attempts: " +
               std::to_string(g_auth.getFailedAttempts()) + ")");
        return;
    }
    g_currentUser = u;
    SetTxt(GetDlgItem(g_hMain, ID_LOGIN_STATUS), "");
    SetTxt(GetDlgItem(g_hMain, ID_LOGIN_PASS), "");

    int code = g_otp.generateOTP();
    SetTxt(GetDlgItem(g_hMain, ID_OTP_DISPLAY),
           "Generated OTP (demo only, normally sent via SMS/email): " + std::to_string(code));
    SetTxt(GetDlgItem(g_hMain, ID_OTP_INPUT), "");
    SetTxt(GetDlgItem(g_hMain, ID_OTP_STATUS), "");

    g_state = STATE_OTP;
    UpdateView();
}

static void DoOtpVerify() {
    std::string entered = GetTxt(GetDlgItem(g_hMain, ID_OTP_INPUT));
    int val = atoi(entered.c_str());
    if (!g_otp.checkOTP(val)) {
        SetTxt(GetDlgItem(g_hMain, ID_OTP_STATUS), "Incorrect OTP. Please try again.");
        SecurityLog::addLog("OTP verification FAILED.");
        return;
    }
    SecurityLog::addLog("OTP verification SUCCESS.");

    SetTxt(GetDlgItem(g_hMain, ID_WELCOME_LABEL),
           "Logged in as: " + g_currentUser->getUsername() + " (" + g_currentUser->getRole() + ")");

    // Admin-only nav button
    EnableWindow(GetDlgItem(g_hMain, ID_NAV_USERS), g_currentUser->getRole() == "Admin");

    g_panel = (g_currentUser->getRole() == "Admin") ? PANEL_USERS : PANEL_DEVICES;
    g_state = STATE_DASHBOARD;
    RefreshUserList();
    RefreshDeviceList();
    RefreshFirewallView();
    RefreshLogsList();
    UpdateView();
}

static void DoLogout() {
    if (g_currentUser) SecurityLog::addLog("User logged out: " + g_currentUser->getUsername());
    g_currentUser = nullptr;
    SetTxt(GetDlgItem(g_hMain, ID_LOGIN_USER), "");
    SetTxt(GetDlgItem(g_hMain, ID_LOGIN_PASS), "");
    g_state = STATE_LOGIN;
    UpdateView();
}

static void RefreshUserList() {
    HWND lb = GetDlgItem(g_hMain, ID_USER_LIST);
    SendMessageA(lb, LB_RESETCONTENT, 0, 0);
    for (auto& u : g_users) SendMessageA(lb, LB_ADDSTRING, 0, (LPARAM)u->displayInfo().c_str());
}

static void DoAddUser() {
    std::string uname = GetTxt(GetDlgItem(g_hMain, ID_USER_NAME));
    std::string pass = GetTxt(GetDlgItem(g_hMain, ID_USER_PASS));
    std::string email = GetTxt(GetDlgItem(g_hMain, ID_USER_EMAIL));
    if (uname.empty() || pass.empty()) {
        MessageBoxA(g_hMain, "Username and password are required.", "Missing info", MB_ICONWARNING);
        return;
    }
    int sel = (int)SendMessageA(GetDlgItem(g_hMain, ID_USER_ROLE_COMBO), CB_GETCURSEL, 0, 0);
    if (sel == 0) g_users.push_back(std::make_shared<Admin>(g_nextUserId++, uname, pass, email));
    else g_users.push_back(std::make_shared<SecurityAnalyst>(g_nextUserId++, uname, pass, email));
    SecurityLog::addLog("New user added: " + uname);

    SetTxt(GetDlgItem(g_hMain, ID_USER_NAME), "");
    SetTxt(GetDlgItem(g_hMain, ID_USER_PASS), "");
    SetTxt(GetDlgItem(g_hMain, ID_USER_EMAIL), "");
    RefreshUserList();
    RefreshLogsList();
}

static void DoRemoveUser() {
    std::string idStr = GetTxt(GetDlgItem(g_hMain, ID_USER_REMOVE_ID));
    int id = atoi(idStr.c_str());
    auto it = std::remove_if(g_users.begin(), g_users.end(),
                              [id](const std::shared_ptr<User>& u) { return u->getId() == id; });
    if (it != g_users.end()) {
        g_users.erase(it, g_users.end());
        SecurityLog::addLog("User removed. ID: " + std::to_string(id));
        RefreshUserList();
        RefreshLogsList();
    } else {
        MessageBoxA(g_hMain, "No user with that ID.", "Not found", MB_ICONINFORMATION);
    }
    SetTxt(GetDlgItem(g_hMain, ID_USER_REMOVE_ID), "");
}

static void RefreshDeviceList() {
    HWND lb = GetDlgItem(g_hMain, ID_DEV_LIST);
    SendMessageA(lb, LB_RESETCONTENT, 0, 0);
    for (auto& d : g_devices) SendMessageA(lb, LB_ADDSTRING, 0, (LPARAM)d.displayInfo().c_str());
}

static void DoAddDevice() {
    std::string name = GetTxt(GetDlgItem(g_hMain, ID_DEV_NAME));
    std::string type = GetTxt(GetDlgItem(g_hMain, ID_DEV_TYPE));
    std::string ip = GetTxt(GetDlgItem(g_hMain, ID_DEV_IP));
    if (name.empty() || ip.empty()) {
        MessageBoxA(g_hMain, "Device name and IP are required.", "Missing info", MB_ICONWARNING);
        return;
    }
    g_devices.push_back(Device(g_nextDeviceId++, name, type, ip, "Online"));
    SecurityLog::addLog("New device added: " + name + " (" + ip + ")");
    SetTxt(GetDlgItem(g_hMain, ID_DEV_NAME), "");
    SetTxt(GetDlgItem(g_hMain, ID_DEV_TYPE), "");
    SetTxt(GetDlgItem(g_hMain, ID_DEV_IP), "");
    RefreshDeviceList();
    RefreshLogsList();
}

static void DoChangeDeviceStatus() {
    std::string idStr = GetTxt(GetDlgItem(g_hMain, ID_DEV_STATUS_ID));
    int id = atoi(idStr.c_str());
    int sel = (int)SendMessageA(GetDlgItem(g_hMain, ID_DEV_STATUS_COMBO), CB_GETCURSEL, 0, 0);
    const char* statuses[] = {"Online", "Offline", "Quarantined"};
    std::string newStatus = statuses[sel < 0 ? 0 : sel];

    bool found = false;
    for (auto& d : g_devices) {
        if (d.getId() == id) {
            d.setStatus(newStatus);
            found = true;
            SecurityLog::addLog("Device status updated. ID: " + std::to_string(id) + " -> " + newStatus);
            break;
        }
    }
    if (!found) MessageBoxA(g_hMain, "No device with that ID.", "Not found", MB_ICONINFORMATION);
    RefreshDeviceList();
    RefreshLogsList();
}

static void DoRunAttack() {
    std::string target = GetTxt(GetDlgItem(g_hMain, ID_ATK_TARGET));
    if (target.empty()) {
        MessageBoxA(g_hMain, "Please enter a simulated target name/IP.", "Missing target", MB_ICONWARNING);
        return;
    }
    int sel = (int)SendMessageA(GetDlgItem(g_hMain, ID_ATK_TYPE_COMBO), CB_GETCURSEL, 0, 0);
    std::unique_ptr<CyberAttack> attack;
    if (sel == 0) attack = std::make_unique<BruteForceAttack>(target);
    else if (sel == 1) attack = std::make_unique<PhishingAttack>(target);
    else attack = std::make_unique<DDoSAttack>(target);

    std::string result = attack->executeAttack();
    g_attackHistory.push_back(attack->getName() + " on " + target);

    HWND out = GetDlgItem(g_hMain, ID_ATK_OUTPUT);
    std::string cur = GetTxt(out);
    std::string add = "----------------------------------------\r\n" + result + "\r\n";
    SetTxt(out, cur + add);
    SendMessageA(out, EM_SETSEL, -1, -1);
    SendMessageA(out, EM_SCROLLCARET, 0, 0);
    RefreshLogsList();
}

static void RefreshFirewallView() {
    SetTxt(GetDlgItem(g_hMain, ID_FW_STATUS_LABEL),
           std::string("Firewall Status: ") + (g_firewall.isActive() ? "ACTIVE" : "INACTIVE"));
    HWND lb = GetDlgItem(g_hMain, ID_FW_RULES_LIST);
    SendMessageA(lb, LB_RESETCONTENT, 0, 0);
    for (auto& r : g_firewall.getRules()) SendMessageA(lb, LB_ADDSTRING, 0, (LPARAM)r.c_str());
}

static void DoToggleFirewall() {
    g_firewall.toggleStatus();
    RefreshFirewallView();
    RefreshLogsList();
}

static void DoAddFirewallRule() {
    std::string rule = GetTxt(GetDlgItem(g_hMain, ID_FW_NEW_RULE));
    if (rule.empty()) return;
    g_firewall.addRule(rule);
    SetTxt(GetDlgItem(g_hMain, ID_FW_NEW_RULE), "");
    RefreshFirewallView();
    RefreshLogsList();
}

static void DoInspectActivity() {
    std::string activity = GetTxt(GetDlgItem(g_hMain, ID_FW_ACTIVITY));
    if (activity.empty()) return;
    std::string result = g_firewall.inspectActivity(activity);
    HWND out = GetDlgItem(g_hMain, ID_FW_OUTPUT);
    std::string cur = GetTxt(out);
    std::string add = "[Firewall] Inspecting: " + activity + "\r\n" + result +
                       "\r\n----------------------------------------\r\n";
    SetTxt(out, cur + add);
    SendMessageA(out, EM_SETSEL, -1, -1);
    SendMessageA(out, EM_SCROLLCARET, 0, 0);
    SetTxt(GetDlgItem(g_hMain, ID_FW_ACTIVITY), "");
    RefreshLogsList();
}

static void RefreshLogsList() {
    HWND lb = GetDlgItem(g_hMain, ID_LOGS_LIST);
    SendMessageA(lb, LB_RESETCONTENT, 0, 0);
    const auto& logs = SecurityLog::getLogs();
    if (logs.empty()) {
        SendMessageA(lb, LB_ADDSTRING, 0, (LPARAM)"No logs recorded yet.");
        return;
    }
    int i = 1;
    for (auto& l : logs) {
        std::string line = std::to_string(i++) + ". " + l;
        SendMessageA(lb, LB_ADDSTRING, 0, (LPARAM)line.c_str());
    }
}

static void DoGenerateReport() {
    std::string report = Report::generate(g_users, g_devices, g_attackHistory, g_firewall);
    SetTxt(GetDlgItem(g_hMain, ID_REPORT_OUTPUT), report);
}

// -----------------------------------------------------------
// View switching
// -----------------------------------------------------------
static void UpdateView() {
    HideGroup(g_loginControls);
    HideGroup(g_otpControls);
    HideGroup(g_sidebarControls);
    HideGroup(g_usersControls);
    HideGroup(g_devicesControls);
    HideGroup(g_attacksControls);
    HideGroup(g_firewallControls);
    HideGroup(g_logsControls);
    HideGroup(g_reportControls);

    if (g_state == STATE_LOGIN) {
        ShowGroup(g_loginControls);
    } else if (g_state == STATE_OTP) {
        ShowGroup(g_otpControls);
    } else {
        ShowGroup(g_sidebarControls);
        switch (g_panel) {
            case PANEL_USERS: ShowGroup(g_usersControls); break;
            case PANEL_DEVICES: ShowGroup(g_devicesControls); break;
            case PANEL_ATTACKS: ShowGroup(g_attacksControls); break;
            case PANEL_FIREWALL: ShowGroup(g_firewallControls); break;
            case PANEL_LOGS: ShowGroup(g_logsControls); break;
            case PANEL_REPORT: ShowGroup(g_reportControls); break;
        }
    }
    InvalidateRect(g_hMain, nullptr, TRUE);
}

static void GoToPanel(DashPanel p) { g_panel = p; UpdateView(); }

// -----------------------------------------------------------
// UI construction
// -----------------------------------------------------------
static void BuildLoginUI(HWND parent) {
    int x = 380, y = 180;
    MakeCtl("STATIC", "Login", WS_CHILD | SS_CENTER, x, y, 240, 24, parent, 0, &g_loginControls);
    MakeCtl("STATIC", "Username:", WS_CHILD, x, y + 40, 240, 18, parent, 0, &g_loginControls);
    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER, x, y + 60, 240, 24, parent, ID_LOGIN_USER, &g_loginControls);
    MakeCtl("STATIC", "Password:", WS_CHILD, x, y + 92, 240, 18, parent, 0, &g_loginControls);
    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER | ES_PASSWORD, x, y + 112, 240, 24, parent, ID_LOGIN_PASS, &g_loginControls);
    MakeCtl("BUTTON", "Login", WS_CHILD | BS_PUSHBUTTON, x, y + 150, 240, 30, parent, ID_LOGIN_BTN, &g_loginControls);
    MakeCtl("STATIC", "", WS_CHILD, x, y + 188, 300, 36, parent, ID_LOGIN_STATUS, &g_loginControls);
    MakeCtl("STATIC", "Default logins: admin/admin123  or  analyst/analyst123",
            WS_CHILD, x - 20, y + 230, 340, 18, parent, 0, &g_loginControls);
}

static void BuildOtpUI(HWND parent) {
    int x = 340, y = 200;
    MakeCtl("STATIC", "Two-Factor Authentication", WS_CHILD | SS_CENTER, x, y, 320, 24, parent, 0, &g_otpControls);
    MakeCtl("STATIC", "", WS_CHILD, x, y + 36, 320, 40, parent, ID_OTP_DISPLAY, &g_otpControls);
    MakeCtl("STATIC", "Enter OTP:", WS_CHILD, x, y + 84, 320, 18, parent, 0, &g_otpControls);
    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER, x, y + 104, 200, 24, parent, ID_OTP_INPUT, &g_otpControls);
    MakeCtl("BUTTON", "Verify", WS_CHILD | BS_PUSHBUTTON, x, y + 140, 200, 30, parent, ID_OTP_BTN, &g_otpControls);
    MakeCtl("STATIC", "", WS_CHILD, x, y + 178, 320, 30, parent, ID_OTP_STATUS, &g_otpControls);
}

static void BuildSidebar(HWND parent) {
    MakeCtl("STATIC", "", WS_CHILD, 0, 0, 900, 26, parent, ID_WELCOME_LABEL, &g_sidebarControls);
    int y = 40, x = 10, w = 160, h = 32, gap = 6;
    MakeCtl("BUTTON", "User Management", WS_CHILD | BS_PUSHBUTTON, x, y, w, h, parent, ID_NAV_USERS, &g_sidebarControls);
    MakeCtl("BUTTON", "Devices", WS_CHILD | BS_PUSHBUTTON, x, y += h + gap, w, h, parent, ID_NAV_DEVICES, &g_sidebarControls);
    MakeCtl("BUTTON", "Attack Simulation", WS_CHILD | BS_PUSHBUTTON, x, y += h + gap, w, h, parent, ID_NAV_ATTACKS, &g_sidebarControls);
    MakeCtl("BUTTON", "Firewall", WS_CHILD | BS_PUSHBUTTON, x, y += h + gap, w, h, parent, ID_NAV_FIREWALL, &g_sidebarControls);
    MakeCtl("BUTTON", "Security Logs", WS_CHILD | BS_PUSHBUTTON, x, y += h + gap, w, h, parent, ID_NAV_LOGS, &g_sidebarControls);
    MakeCtl("BUTTON", "Reports", WS_CHILD | BS_PUSHBUTTON, x, y += h + gap, w, h, parent, ID_NAV_REPORT, &g_sidebarControls);
    MakeCtl("BUTTON", "Logout", WS_CHILD | BS_PUSHBUTTON, x, y += h + gap + 20, w, h, parent, ID_NAV_LOGOUT, &g_sidebarControls);
}

static const int CONTENT_X = 190;

static void BuildUsersPanel(HWND parent) {
    int x = CONTENT_X;
    MakeCtl("STATIC", "Users:", WS_CHILD, x, 42, 200, 18, parent, 0, &g_usersControls);
    MakeCtl("LISTBOX", "", WS_CHILD | WS_BORDER | WS_VSCROLL | LBS_NOTIFY,
            x, 62, 680, 180, parent, ID_USER_LIST, &g_usersControls);

    int y = 256;
    MakeCtl("STATIC", "Add User - Username:", WS_CHILD, x, y, 140, 18, parent, 0, &g_usersControls);
    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER, x + 150, y - 2, 140, 22, parent, ID_USER_NAME, &g_usersControls);
    MakeCtl("STATIC", "Password:", WS_CHILD, x + 300, y, 70, 18, parent, 0, &g_usersControls);
    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER | ES_PASSWORD, x + 375, y - 2, 120, 22, parent, ID_USER_PASS, &g_usersControls);
    MakeCtl("STATIC", "Email:", WS_CHILD, x + 505, y, 50, 18, parent, 0, &g_usersControls);
    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER, x + 555, y - 2, 130, 22, parent, ID_USER_EMAIL, &g_usersControls);

    y += 32;
    MakeCtl("STATIC", "Role:", WS_CHILD, x, y, 50, 18, parent, 0, &g_usersControls);
    HWND combo = MakeCtl("COMBOBOX", "", WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL,
                          x + 150, y - 2, 140, 100, parent, ID_USER_ROLE_COMBO, &g_usersControls);
    SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)"Admin");
    SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)"Security Analyst");
    SendMessageA(combo, CB_SETCURSEL, 0, 0);
    MakeCtl("BUTTON", "Add User", WS_CHILD | BS_PUSHBUTTON, x + 300, y - 2, 100, 26, parent, ID_USER_ADD_BTN, &g_usersControls);

    y += 40;
    MakeCtl("STATIC", "Remove User - ID:", WS_CHILD, x, y, 120, 18, parent, 0, &g_usersControls);
    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER, x + 150, y - 2, 80, 22, parent, ID_USER_REMOVE_ID, &g_usersControls);
    MakeCtl("BUTTON", "Remove User", WS_CHILD | BS_PUSHBUTTON, x + 250, y - 2, 120, 26, parent, ID_USER_REMOVE_BTN, &g_usersControls);
}

static void BuildDevicesPanel(HWND parent) {
    int x = CONTENT_X;
    MakeCtl("STATIC", "Devices:", WS_CHILD, x, 42, 200, 18, parent, 0, &g_devicesControls);
    MakeCtl("LISTBOX", "", WS_CHILD | WS_BORDER | WS_VSCROLL | LBS_NOTIFY,
            x, 62, 680, 180, parent, ID_DEV_LIST, &g_devicesControls);

    int y = 256;
    MakeCtl("STATIC", "Add Device - Name:", WS_CHILD, x, y, 130, 18, parent, 0, &g_devicesControls);
    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER, x + 140, y - 2, 120, 22, parent, ID_DEV_NAME, &g_devicesControls);
    MakeCtl("STATIC", "Type:", WS_CHILD, x + 270, y, 40, 18, parent, 0, &g_devicesControls);
    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER, x + 315, y - 2, 110, 22, parent, ID_DEV_TYPE, &g_devicesControls);
    MakeCtl("STATIC", "IP:", WS_CHILD, x + 435, y, 30, 18, parent, 0, &g_devicesControls);
    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER, x + 465, y - 2, 110, 22, parent, ID_DEV_IP, &g_devicesControls);
    MakeCtl("BUTTON", "Add Device", WS_CHILD | BS_PUSHBUTTON, x + 585, y - 2, 100, 26, parent, ID_DEV_ADD_BTN, &g_devicesControls);

    y += 40;
    MakeCtl("STATIC", "Change Status - Device ID:", WS_CHILD, x, y, 160, 18, parent, 0, &g_devicesControls);
    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER, x + 170, y - 2, 70, 22, parent, ID_DEV_STATUS_ID, &g_devicesControls);
    HWND combo = MakeCtl("COMBOBOX", "", WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL,
                          x + 250, y - 2, 130, 100, parent, ID_DEV_STATUS_COMBO, &g_devicesControls);
    SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)"Online");
    SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)"Offline");
    SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)"Quarantined");
    SendMessageA(combo, CB_SETCURSEL, 0, 0);
    MakeCtl("BUTTON", "Update Status", WS_CHILD | BS_PUSHBUTTON, x + 400, y - 2, 120, 26, parent, ID_DEV_STATUS_BTN, &g_devicesControls);
}

static void BuildAttacksPanel(HWND parent) {
    int x = CONTENT_X;
    MakeCtl("STATIC", "Educational simulation only - no real network activity is performed.",
            WS_CHILD, x, 42, 500, 18, parent, 0, &g_attacksControls);

    MakeCtl("STATIC", "Attack Type:", WS_CHILD, x, 72, 90, 18, parent, 0, &g_attacksControls);
    HWND combo = MakeCtl("COMBOBOX", "", WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL,
                          x + 100, 70, 180, 100, parent, ID_ATK_TYPE_COMBO, &g_attacksControls);
    SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)"Brute Force Attack");
    SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)"Phishing Attack");
    SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)"DDoS Attack");
    SendMessageA(combo, CB_SETCURSEL, 0, 0);

    MakeCtl("STATIC", "Target:", WS_CHILD, x + 300, 72, 60, 18, parent, 0, &g_attacksControls);
    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER, x + 360, 70, 180, 22, parent, ID_ATK_TARGET, &g_attacksControls);
    MakeCtl("BUTTON", "Run Attack", WS_CHILD | BS_PUSHBUTTON, x + 560, 68, 110, 26, parent, ID_ATK_RUN_BTN, &g_attacksControls);

    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL,
            x, 108, 680, 340, parent, ID_ATK_OUTPUT, &g_attacksControls);
}

static void BuildFirewallPanel(HWND parent) {
    int x = CONTENT_X;
    MakeCtl("STATIC", "", WS_CHILD, x, 42, 300, 20, parent, ID_FW_STATUS_LABEL, &g_firewallControls);
    MakeCtl("BUTTON", "Toggle Active/Inactive", WS_CHILD | BS_PUSHBUTTON, x + 310, 40, 170, 26, parent, ID_FW_TOGGLE_BTN, &g_firewallControls);

    MakeCtl("STATIC", "Rules:", WS_CHILD, x, 74, 100, 18, parent, 0, &g_firewallControls);
    MakeCtl("LISTBOX", "", WS_CHILD | WS_BORDER | WS_VSCROLL, x, 94, 680, 90, parent, ID_FW_RULES_LIST, &g_firewallControls);

    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER, x, 194, 400, 22, parent, ID_FW_NEW_RULE, &g_firewallControls);
    MakeCtl("BUTTON", "Add Rule", WS_CHILD | BS_PUSHBUTTON, x + 410, 192, 100, 26, parent, ID_FW_ADD_RULE_BTN, &g_firewallControls);

    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER, x, 230, 400, 22, parent, ID_FW_ACTIVITY, &g_firewallControls);
    MakeCtl("BUTTON", "Inspect Activity", WS_CHILD | BS_PUSHBUTTON, x + 410, 228, 130, 26, parent, ID_FW_INSPECT_BTN, &g_firewallControls);

    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL,
            x, 268, 680, 180, parent, ID_FW_OUTPUT, &g_firewallControls);
}

static void BuildLogsPanel(HWND parent) {
    int x = CONTENT_X;
    MakeCtl("BUTTON", "Refresh Logs", WS_CHILD | BS_PUSHBUTTON, x, 42, 120, 26, parent, ID_LOGS_REFRESH_BTN, &g_logsControls);
    MakeCtl("LISTBOX", "", WS_CHILD | WS_BORDER | WS_VSCROLL, x, 76, 680, 420, parent, ID_LOGS_LIST, &g_logsControls);
}

static void BuildReportPanel(HWND parent) {
    int x = CONTENT_X;
    MakeCtl("BUTTON", "Generate Report", WS_CHILD | BS_PUSHBUTTON, x, 42, 140, 26, parent, ID_REPORT_BTN, &g_reportControls);
    MakeCtl("EDIT", "", WS_CHILD | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL,
            x, 76, 680, 420, parent, ID_REPORT_OUTPUT, &g_reportControls);
}

// -----------------------------------------------------------
// Window procedure
// -----------------------------------------------------------
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            NONCLIENTMETRICSA ncm = { sizeof(ncm) };
            SystemParametersInfoA(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
            g_hFont = CreateFontIndirectA(&ncm.lfMessageFont);

            BuildLoginUI(hwnd);
            BuildOtpUI(hwnd);
            BuildSidebar(hwnd);
            BuildUsersPanel(hwnd);
            BuildDevicesPanel(hwnd);
            BuildAttacksPanel(hwnd);
            BuildFirewallPanel(hwnd);
            BuildLogsPanel(hwnd);
            BuildReportPanel(hwnd);

            UpdateView();
            return 0;
        }
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            switch (id) {
                case ID_LOGIN_BTN: DoLogin(); break;
                case ID_OTP_BTN: DoOtpVerify(); break;
                case ID_NAV_USERS: GoToPanel(PANEL_USERS); break;
                case ID_NAV_DEVICES: GoToPanel(PANEL_DEVICES); break;
                case ID_NAV_ATTACKS: GoToPanel(PANEL_ATTACKS); break;
                case ID_NAV_FIREWALL: GoToPanel(PANEL_FIREWALL); break;
                case ID_NAV_LOGS: RefreshLogsList(); GoToPanel(PANEL_LOGS); break;
                case ID_NAV_REPORT: GoToPanel(PANEL_REPORT); break;
                case ID_NAV_LOGOUT: DoLogout(); break;
                case ID_USER_ADD_BTN: DoAddUser(); break;
                case ID_USER_REMOVE_BTN: DoRemoveUser(); break;
                case ID_DEV_ADD_BTN: DoAddDevice(); break;
                case ID_DEV_STATUS_BTN: DoChangeDeviceStatus(); break;
                case ID_ATK_RUN_BTN: DoRunAttack(); break;
                case ID_FW_TOGGLE_BTN: DoToggleFirewall(); break;
                case ID_FW_ADD_RULE_BTN: DoAddFirewallRule(); break;
                case ID_FW_INSPECT_BTN: DoInspectActivity(); break;
                case ID_LOGS_REFRESH_BTN: RefreshLogsList(); break;
                case ID_REPORT_BTN: DoGenerateReport(); break;
            }
            return 0;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

// -----------------------------------------------------------
// Entry point
// -----------------------------------------------------------
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    srand((unsigned int)time(nullptr));

    g_users.push_back(std::make_shared<Admin>(g_nextUserId++, "admin", "admin123", "admin@system.com"));
    g_users.push_back(std::make_shared<SecurityAnalyst>(g_nextUserId++, "analyst", "analyst123", "analyst@system.com"));

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES | ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icc);

    const char* CLASS_NAME = "CyberSecuritySimWindow";
    WNDCLASSA wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    RegisterClassA(&wc);

    g_hMain = CreateWindowExA(0, CLASS_NAME, "Cyber Security Simulation System",
                               WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX,
                               CW_USEDEFAULT, CW_USEDEFAULT, 920, 620,
                               nullptr, nullptr, hInstance, nullptr);

    ShowWindow(g_hMain, nCmdShow);
    UpdateWindow(g_hMain);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
