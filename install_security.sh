#!/bin/sh
# Author : iletymaszlat (enhanced version)
# Skrypt instaluje rozszerzone zabezpieczenia systemowe i monitoruje podejrzane działania

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' 

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_section() {
    echo -e "\n${PURPLE}=== $1 ===${NC}"
}

check_root() {
    if [ "$(id -u)" != "0" ]; then
        print_error "Ten skrypt musi być uruchomiony jako root"
        print_error "This script must be run as root"
        exit 1
    fi
}

check_error() {
    if [ $? -ne 0 ]; then
        print_error "Wystąpił błąd podczas: $1"
        print_error "An error occurred while: $1"
        exit 1
    fi
}

check_root

print_section "Tworzenie kopii zapasowej"
backup_dir="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$backup_dir"
cp -r /etc/audit /etc/selinux /etc/sysctl.conf /etc/passwd /etc/group "$backup_dir/"
print_success "Utworzono kopię zapasową w $backup_dir"

print_section "Instalacja narzędzi bezpieczeństwa"
print_info "Rozpoczynam instalację pakietów..."
if command -v apt-get &> /dev/null; then
    apt-get update
    apt-get install -y auditd audispd-plugins fail2ban rkhunter chkrootkit aide ufw lynis \
    unattended-upgrades needrestart
    check_error "instalacji narzędzi bezpieczeństwa"
elif command -v yum &> /dev/null; then
    yum -y install audit audit-libs audispd-plugins fail2ban rkhunter chkrootkit aide ufw lynis \
    pam_cracklib dnf-automatic
    check_error "instalacji narzędzi bezpieczeństwa"
fi
print_success "Zainstalowano narzędzia bezpieczeństwa"
if command -v apt-get &> /dev/null; then
    echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";' > /etc/apt/apt.conf.d/20auto-upgrades
fi

configure_ssh_keys() {
    local username=$1
    local user_home=$(getent passwd "$username" | cut -d: -f6)
    

    mkdir -p "${user_home}/.ssh"
    chmod 700 "${user_home}/.ssh"
    
 
    print_info "Generowanie kluczy SSH dla użytkownika $username..."
    ssh-keygen -t ed25519 -f "${user_home}/.ssh/id_ed25519" -N ""
    

    cat "${user_home}/.ssh/id_ed25519.pub" >> "${user_home}/.ssh/authorized_keys"
    chmod 600 "${user_home}/.ssh/authorized_keys"
    chown -R "$username:$username" "${user_home}/.ssh"
    
    print_success "Klucze SSH zostały wygenerowane:"
    print_info "Klucz prywatny: ${user_home}/.ssh/id_ed25519"
    print_info "Klucz publiczny: ${user_home}/.ssh/id_ed25519.pub"
    print_warning "ZAPISZ klucz prywatny w bezpiecznym miejscu! Będzie potrzebny do logowania."
}


print_section "Konfiguracja SSH"
print_info "Tworzenie kopii zapasowej konfiguracji SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak


read -p "$(echo -e "${YELLOW}Czy chcesz zmienić domyślny port SSH (22)? [t/N]: ${NC}")" change_port
if [[ "$change_port" =~ ^[Tt]$ ]]; then
    while true; do
        read -p "$(echo -e "${BLUE}Podaj nowy port SSH (1024-65535): ${NC}")" ssh_port
        if [[ "$ssh_port" =~ ^[0-9]+$ ]] && [ "$ssh_port" -ge 1024 ] && [ "$ssh_port" -le 65535 ]; then
            break
        else
            print_error "Nieprawidłowy port. Wybierz port między 1024 a 65535."
        fi
    done
    
    read -p "$(echo -e "${YELLOW}Czy chcesz automatycznie otworzyć ten port w firewallu? [T/n]: ${NC}")" configure_firewall
    if [[ ! "$configure_firewall" =~ ^[Nn]$ ]]; then
        if command -v ufw &> /dev/null; then
            ufw allow "$ssh_port/tcp"
            print_success "Port $ssh_port został otwarty w UFW"
        elif command -v firewall-cmd &> /dev/null; then
            firewall-cmd --permanent --add-port="$ssh_port/tcp"
            firewall-cmd --reload
            print_success "Port $ssh_port został otwarty w firewalld"
        fi
    fi
else
    ssh_port=22
fi

read -p "$(echo -e "${YELLOW}Czy chcesz skonfigurować uwierzytelnianie kluczami SSH? [T/n]: ${NC}")" use_keys
if [[ ! "$use_keys" =~ ^[Nn]$ ]]; then
    read -p "$(echo -e "${YELLOW}Czy wygenerować nowe klucze SSH? [T/n]: ${NC}")" generate_keys
    if [[ ! "$generate_keys" =~ ^[Nn]$ ]]; then
        read -p "$(echo -e "${BLUE}Podaj nazwę użytkownika, dla którego wygenerować klucze: ${NC}")" username
        if id "$username" &>/dev/null; then
            configure_ssh_keys "$username"
        else
            print_error "Użytkownik $username nie istnieje"
            exit 1
        fi
    fi
fi

print_info "Aktualizacja konfiguracji SSH..."
cat << EOF > /etc/ssh/sshd_config
# Konfiguracja SSH wygenerowana przez skrypt bezpieczeństwa
Port $ssh_port
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
Protocol 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitEmptyPasswords no
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
PermitUserEnvironment no
MaxStartups 3:50:10
EOF

print_info "Restartowanie usługi SSH..."
systemctl restart sshd
if [ $? -eq 0 ]; then
    print_success "Konfiguracja SSH została zaktualizowana"
    if [ "$ssh_port" != "22" ]; then
        print_warning "SSH nasłuchuje teraz na porcie $ssh_port"
        print_warning "Upewnij się, że możesz się połączyć przez nowy port przed zamknięciem obecnej sesji!"
    fi
    if [[ ! "$use_keys" =~ ^[Nn]$ ]]; then
        print_warning "Logowanie hasłem zostało wyłączone - używaj kluczy SSH"
    fi
else
    print_error "Wystąpił problem podczas restartowania SSH"
    print_info "Przywracanie kopii zapasowej..."
    cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    systemctl restart sshd
fi
echo "Konfiguracja fail2ban..."
cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
systemctl enable fail2ban
systemctl restart fail2ban

cat << EOF > /etc/audit/rules.d/audit.rules
# Monitorowanie zmian w plikach konfiguracyjnych
-w /etc/audit/ -p wa -k config_change
-w /etc/sysctl.conf -p wa -k sysctl_change
-w /etc/passwd -p wa -k user_change
-w /etc/group -p wa -k group_change
-w /etc/shadow -p wa -k shadow_change
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/sudoers -p wa -k sudoers_change

# Monitorowanie nieudanych prób logowania
-w /var/log/faillog -p wa -k login_failures
-w /var/log/lastlog -p wa -k login_activity

# Monitorowanie procesów
-w /usr/bin/sudo -p x -k sudo_usage
-w /usr/bin/su -p x -k su_usage
-w /bin/ping -p x -k ping_usage

# Monitorowanie montowania systemów plików
-a exit,always -F arch=b64 -S mount -S umount2 -k mount_operations

# Monitorowanie modyfikacji modułów jądra
-w /sbin/insmod -p x -k module_insertion
-w /sbin/rmmod -p x -k module_removal
-w /sbin/modprobe -p x -k module_insertion

# Monitorowanie operacji sieciowych
-a exit,always -F arch=b64 -S socket -k network_socket
EOF

echo "Instalacja SELinux..."
if command -v apt-get &> /dev/null; then
    apt-get install -y selinux-basics selinux-policy-default policycoreutils
elif command -v yum &> /dev/null; then
    yum -y install selinux-policy selinux-policy-targeted policycoreutils
fi

cat << EOF > /etc/sysctl.d/99-security.conf
# Ochrona przed atakami typu SYN flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# Wyłączenie IP forwarding
net.ipv4.ip_forward = 0

# Wyłączenie odpowiedzi na pingi
net.ipv4.icmp_echo_ignore_all = 1

# Ochrona przed atakami ICMP
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Włączenie ochrony przed atakami spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Wyłączenie przyjmowania pakietów redirect
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Wyłączenie source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Zwiększenie zakresu portów efemerycznych
net.ipv4.ip_local_port_range = 32768 65535
EOF

sysctl -p /etc/sysctl.d/99-security.conf

cat << EOF >> /etc/security/limits.conf
* hard core 0
* soft nproc 1000
* hard nproc 2000
* soft nofile 4096
* hard nofile 8192
EOF

aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

augenrules --load
systemctl restart auditd

rkhunter --update
rkhunter --propupd
rkhunter --check --skip-keypress

print_section "Podsumowanie"
print_success "Instalacja i konfiguracja zakończona pomyślnie."
echo -e "${CYAN}Wykonane usprawnienia:${NC}"
echo -e "${GREEN}1. Zainstalowano dodatkowe narzędzia bezpieczeństwa (fail2ban, rkhunter, aide)${NC}"
echo -e "${GREEN}2. Skonfigurowano automatyczne aktualizacje systemu${NC}"
echo -e "${GREEN}3. Wzmocniono konfigurację SSH${NC}"
echo -e "${GREEN}4. Dodano rozszerzone reguły audytu${NC}"
echo -e "${GREEN}5. Skonfigurowano zabezpieczenia sieciowe (sysctl)${NC}"
echo -e "${GREEN}6. Skonfigurowano limity systemowe${NC}"
echo -e "${GREEN}7. Zainicjalizowano system AIDE${NC}"
echo -e "${GREEN}8. Wykonano pierwszy skan rkhunter${NC}"
echo ""
print_warning "Wymagane jest ponowne uruchomienie serwera, aby wszystkie zmiany zostały zastosowane."
print_info "Możesz uruchomić ponownie serwer komendą: reboot"
echo ""
print_warning "WAŻNE: Jeżeli w trakcie działania skryptu wybrałeś włączenie logowania do ssh poprzez klucze," 
print_warning "upewnij się, że masz dostęp do serwera przez klucz SSH przed restartem,"
print_warning "ponieważ logowanie hasłem zostało wyłączone!"
