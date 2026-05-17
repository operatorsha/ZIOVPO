#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <csignal>
#include <ctime>
#include <iostream>
#include <sstream>
#include <string>

namespace {

constexpr unsigned short kPort = 18080;
constexpr const char* kAccessToken = "demo-access-token";
constexpr const char* kRefreshToken = "demo-refresh-token";
enum class LicenseMode {
    None,
    Active,
    Expired,
    Blocked
};

std::atomic_bool g_has_license = false;
std::atomic<LicenseMode> g_license_mode = LicenseMode::None;
std::atomic_bool g_running = true;

std::string JsonEscape(const std::string& value) {
    std::string result;
    for (char ch : value) {
        switch (ch) {
        case '\\':
            result += "\\\\";
            break;
        case '"':
            result += "\\\"";
            break;
        case '\n':
            result += "\\n";
            break;
        case '\r':
            result += "\\r";
            break;
        default:
            result += ch;
            break;
        }
    }
    return result;
}

std::string ExtractJsonString(const std::string& json, const std::string& key) {
    const std::string marker = "\"" + key + "\"";
    size_t pos = json.find(marker);
    if (pos == std::string::npos) {
        return {};
    }
    pos = json.find(':', pos);
    if (pos == std::string::npos) {
        return {};
    }
    pos = json.find('"', pos);
    if (pos == std::string::npos) {
        return {};
    }
    ++pos;

    std::string result;
    bool escape = false;
    for (; pos < json.size(); ++pos) {
        char ch = json[pos];
        if (escape) {
            result += ch;
            escape = false;
            continue;
        }
        if (ch == '\\') {
            escape = true;
            continue;
        }
        if (ch == '"') {
            break;
        }
        result += ch;
    }
    return result;
}

std::string LicenseExpiresAt() {
    std::time_t now = std::time(nullptr);
    now += 30 * 24 * 60 * 60;

    std::tm time_info{};
    gmtime_s(&time_info, &now);

    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &time_info);
    return buffer;
}

std::string MakeResponse(int status_code, const std::string& status_text, const std::string& body) {
    std::ostringstream response;
    response << "HTTP/1.1 " << status_code << ' ' << status_text << "\r\n";
    response << "Content-Type: application/json; charset=utf-8\r\n";
    response << "Content-Length: " << body.size() << "\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";
    response << body;
    return response.str();
}

std::string Ok(const std::string& body) {
    return MakeResponse(200, "OK", body);
}

std::string BadRequest(const std::string& message) {
    return MakeResponse(400, "Bad Request", "{\"error\":\"" + JsonEscape(message) + "\"}");
}

std::string Unauthorized(const std::string& message) {
    return MakeResponse(401, "Unauthorized", "{\"error\":\"" + JsonEscape(message) + "\"}");
}

std::string NotFound() {
    return MakeResponse(404, "Not Found", "{\"error\":\"not found\"}");
}

std::string HandleRequest(const std::string& request) {
    const size_t first_line_end = request.find("\r\n");
    if (first_line_end == std::string::npos) {
        return BadRequest("invalid request");
    }

    std::istringstream request_line(request.substr(0, first_line_end));
    std::string method;
    std::string path;
    request_line >> method >> path;

    const size_t body_pos = request.find("\r\n\r\n");
    const std::string body = body_pos == std::string::npos ? std::string{} : request.substr(body_pos + 4);

    if (method == "POST" && path == "/api/auth/login") {
        const std::string login = ExtractJsonString(body, "login");
        const std::string password = ExtractJsonString(body, "password");
        if (login != "test" || password != "test") {
            return Unauthorized("use login test and password test");
        }

        return Ok(
            "{\"accessToken\":\"" + std::string(kAccessToken) +
            "\",\"refreshToken\":\"" + std::string(kRefreshToken) +
            "\",\"login\":\"" + JsonEscape(login) +
            "\",\"accessExpiresIn\":120}"
        );
    }

    if (method == "POST" && path == "/api/auth/refresh") {
        return Ok(
            "{\"accessToken\":\"" + std::string(kAccessToken) +
            "\",\"refreshToken\":\"" + std::string(kRefreshToken) +
            "\",\"accessExpiresIn\":120}"
        );
    }

    if (method == "GET" && path == "/api/license/status") {
        LicenseMode mode = g_license_mode.load();
        if (mode == LicenseMode::Expired) {
            return Ok("{\"hasLicense\":0,\"ticket\":\"\",\"expiresAt\":\"2025-01-01T00:00:00Z\",\"licenseExpiresIn\":60,\"error\":\"license expired\"}");
        }
        if (mode == LicenseMode::Blocked) {
            return Ok("{\"hasLicense\":0,\"ticket\":\"\",\"expiresAt\":\"\",\"licenseExpiresIn\":60,\"error\":\"license blocked\"}");
        }
        if (!g_has_license.load()) {
            return Ok("{\"hasLicense\":0,\"ticket\":\"\",\"expiresAt\":\"\",\"licenseExpiresIn\":60}");
        }

        const std::string expires_at = LicenseExpiresAt();
        return Ok(
            "{\"hasLicense\":1,\"ticket\":\"demo-license-ticket\",\"expiresAt\":\"" +
            expires_at +
            "\",\"licenseExpiresIn\":120}"
        );
    }

    if (method == "POST" && path == "/api/license/activate") {
        const std::string code = ExtractJsonString(body, "activationCode");
        if (code == "EXPIRED-KEY") {
            g_has_license = false;
            g_license_mode = LicenseMode::Expired;
            return BadRequest("license expired");
        }
        if (code == "BLOCKED-KEY") {
            g_has_license = false;
            g_license_mode = LicenseMode::Blocked;
            return BadRequest("license blocked");
        }
        if (code != "DEMO-KEY") {
            return BadRequest("activation code must be DEMO-KEY");
        }

        g_has_license = true;
        g_license_mode = LicenseMode::Active;
        const std::string expires_at = LicenseExpiresAt();
        return Ok(
            "{\"hasLicense\":1,\"ticket\":\"demo-license-ticket\",\"expiresAt\":\"" +
            expires_at +
            "\",\"licenseExpiresIn\":120,\"signature\":\"demo-signature\"}"
        );
    }

    return NotFound();
}

void SignalHandler(int) {
    g_running = false;
}

} // namespace

int main() {
    std::signal(SIGINT, SignalHandler);

    WSADATA wsa_data{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    SOCKET listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket == INVALID_SOCKET) {
        std::cerr << "socket failed: " << WSAGetLastError() << "\n";
        WSACleanup();
        return 1;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(kPort);

    if (bind(listen_socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
        std::cerr << "bind failed: " << WSAGetLastError() << "\n";
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "listen failed: " << WSAGetLastError() << "\n";
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    std::cout << "Mock license server is running on http://127.0.0.1:" << kPort << "\n";
    std::cout << "Login: test, password: test, activation code: DEMO-KEY\n";

    while (g_running.load()) {
        SOCKET client = accept(listen_socket, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            continue;
        }

        std::string request;
        char buffer[4096]{};
        int received = recv(client, buffer, sizeof(buffer), 0);
        if (received > 0) {
            request.assign(buffer, buffer + received);
            const std::string response = HandleRequest(request);
            send(client, response.data(), static_cast<int>(response.size()), 0);
        }

        shutdown(client, SD_BOTH);
        closesocket(client);
    }

    closesocket(listen_socket);
    WSACleanup();
    return 0;
}
