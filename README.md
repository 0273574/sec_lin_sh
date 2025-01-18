# Security Installation Script

## Overview
Ten skrypt automatyzuje proces instalacji i konfiguracji podstawowych narzędzi bezpieczeństwa na serwerach Linux, w tym auditd i SELinux. Został zaprojektowany, aby zapewnić podstawowy poziom monitorowania bezpieczeństwa i kontroli dostępu do systemu.

## Funkcjonalności
- Automatyczna instalacja auditd i audispd-plugins
- Konfiguracja podstawowych reguł audytu systemowego
- Instalacja i konfiguracja SELinux w trybie permissive
- Obsługa systemów bazujących na apt (Debian/Ubuntu) oraz yum (RHEL/CentOS)
- Automatyczne wykrywanie typu systemu i dostosowanie procesu instalacji
- Sprawdzanie błędów na każdym etapie instalacji

## Wymagania
- System operacyjny: Linux (Debian/Ubuntu lub RHEL/CentOS)
- Uprawnienia: root
- Minimum 100MB wolnego miejsca na dysku
- Połączenie z internetem (do pobrania pakietów)

## Instalacja
1. Pobierz skrypt:
```bash
git clone https://github.com/[username]/security-install-script.git
cd security-install-script
```

2. Nadaj uprawnienia do wykonania:
```bash
chmod +x install_security.sh
```

3. Uruchom skrypt:
```bash
sudo ./install_security.sh
```

## Szczegóły implementacji

### Reguły audytu
Skrypt konfiguruje następujące reguły audytu:
- Monitorowanie zmian w plikach konfiguracyjnych `/etc/audit/`
- Śledzenie modyfikacji w `/etc/sysctl.conf`
- Monitorowanie zmian w plikach użytkowników i grup
- Śledzenie nieudanych prób logowania

### Konfiguracja SELinux
- Instalacja podstawowych pakietów SELinux
- Ustawienie trybu permissive w `/etc/selinux/config`
- Automatyczne przygotowanie do ponownego uruchomienia

## Rozwiązywanie problemów

### Znane problemy
1. Na niektórych systemach może być wymagana dodatkowa konfiguracja firewalla
2. W przypadku systemów z już zainstalowanym SELinux, może być wymagana ręczna rekonfiguracja

### Rozwiązania
- Jeśli wystąpią problemy z instalacją pakietów, sprawdź połączenie internetowe i dostępność repozytoriów
- W przypadku błędów SELinux, sprawdź logi systemowe: `journalctl -xe`

## Bezpieczeństwo
- Skrypt wykonuje podstawową konfigurację bezpieczeństwa
- SELinux jest ustawiony w trybie permissive, co oznacza, że tylko loguje naruszenia zasad bez ich blokowania
- Zalecana jest dalsza konfiguracja w zależności od potrzeb środowiska

## Po instalacji
1. Zweryfikuj status auditd:
```bash
systemctl status auditd
```

2. Sprawdź logi audytu:
```bash
ausearch -ts recent
```

3. Potwierdź konfigurację SELinux:
```bash
sestatus
```

4. **WAŻNE**: Wymagane jest ponowne uruchomienie systemu po instalacji

## Wkład i rozwój
- Pull requesty są mile widziane
- Prosimy o zgłaszanie błędów poprzez system Issues na GitHubie
- Przy wprowadzaniu zmian, prosimy o przestrzeganie istniejącego stylu kodu

## Licencja
Ten projekt jest dostępny na licencji MIT. Zobacz plik `LICENSE` dla szczegółów.

## Autor
iletymaszlat

## Podziękowania
Podziękowania dla społeczności open source za narzędzia wykorzystane w tym projekcie.
