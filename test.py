import requests
import ssl
import socket
import time
from urllib.parse import urlparse

# --- Настройки тестов ---
TEST_SUITE = [
    {"id": "CF-02", "provider": "Cloudflare", "url": "https://genshin.jmp.blue/characters/all#"},
    {"id": "CF-03", "provider": "Cloudflare", "url": "https://api.frankfurter.dev/v1/2000-01-01..2002-12-31"},
    {"id": "DO-01", "provider": "DigitalOcean", "url": "https://genderize.io/"},
    {"id": "HE-01", "provider": "Hetzner", "url": "https://bible-api.com/john+1,2,3,4,5,6,7,8,9,10"},
    # Для теста DPI лучше использовать ссылки на файлы > 1MB
    {"id": "HE-02", "provider": "Hetzner", "url": "https://ash-speed.hetzner.com/100MB.bin"},
    {"id": "OVH-01", "provider": "OVH", "url": "https://proof.ovh.net/files/1Mb.dat"},
]

TIMEOUT = 10 # Слегка увеличим таймаут для больших файлов

def print_header(text):
    print("\n" + "="*len(text))
    print(text)
    print("="*len(text))

def check_dpi(url):
    try:
        # Заголовки, чтобы сервер не принял нас за бота
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        with requests.get(url, stream=True, timeout=TIMEOUT, headers=headers) as r:
            r.raise_for_status()
            total = 0
            # Проверяем первые ~2MB, этого достаточно для теста
            for chunk in r.iter_content(chunk_size=8192):
                total += len(chunk)
                if total > 2 * 1024 * 1024:
                    return "Not detected ✅"
            
            # Если загрузка остановилась на 16-24KB - это DPI
            if 16 * 1024 <= total <= 24 * 1024:
                return f"Detected❗️ (download stopped at {total // 1024} KB)"
            
            # Если файл скачался полностью и он меньше 2MB - это тоже успех
            return "Not detected ✅"

    except requests.exceptions.RequestException as e:
        return f"Detected❗️ (Connection failed: {e.__class__.__name__})"
    except Exception as e:
        return f"Detected❗️ ({e})"

def check_tls_version(host, port=443, version="TLSv1_3"):
    context = ssl.create_default_context()
    
    if version == "TLSv1_3":
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    elif version == "TLSv1_2":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        raise ValueError("Unknown TLS version")

    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # ИСПРАВЛЕНИЕ: Сравниваем ssock.version() ('TLSv1.3') с version ('TLSv1_3')
                # Для этого заменяем '_' на '.' в нашей переменной
                if ssock.version() == version.replace('_', '.'):
                    return "OK ✅"
                else:
                    return f"Failed (negotiated {ssock.version()})"
    except (socket.timeout, ssl.SSLError, ConnectionResetError, OSError) as e:
        return f"Blocked ❌ ({e.__class__.__name__})"
    except Exception as e:
        return f"Blocked ❌ ({e.__class__.__name__})"


def check_sni_ip(ip, sni, port=443):
    result = {}
    result["TLS 1.3"] = check_tls_version(ip, port, version="TLSv1_3")
    result["TLS 1.2"] = check_tls_version(ip, port, version="TLSv1_2")

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                req = f"GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
                ssock.sendall(req.encode())
                data = ssock.recv(1024)
                if b"HTTP/" in data:
                    result["HTTP"] = "OK ✅"
                else:
                    result["HTTP"] = "Blocked ❌ (no HTTP response)"
    except Exception as e:
        result["HTTP"] = f"Blocked ❌ ({e.__class__.__name__})"
        
    return result

# ... (остальной код с меню остался без изменений) ...

def main_menu():
    print_header("VPN/Провайдер тестер (v2.0)")
    print("1. Общий тест популярных хостингов (DPI + TLS 1.2/1.3)")
    print("2. Тест SNI + IP (ручной ввод)")
    print("0. Выход")
    return input("Выберите пункт меню: ").strip()

def run_general_test():
    print_header("Общий тест DPI и TLS")
    for test in TEST_SUITE:
        url = test["url"]
        host = urlparse(url).hostname
        print(f"\n[{test['id']}] {test['provider']} ({host})")
        print("  DPI:", check_dpi(url))
        print("  TLS 1.3:", check_tls_version(host, version="TLSv1_3"))
        print("  TLS 1.2:", check_tls_version(host, version="TLSv1_2"))

def run_sni_ip_test():
    print_header("Тест SNI + IP")
    ip = input("Введите IP сервера: ").strip()
    sni = input("Введите SNI (домен): ").strip()
    if not ip or not sni:
        print("IP и SNI обязательны!")
        return
    res = check_sni_ip(ip, sni)
    print(f"  TLS 1.3: {res['TLS 1.3']}")
    print(f"  TLS 1.2: {res['TLS 1.2']}")
    print(f"  HTTP: {res['HTTP']}")

if __name__ == "__main__":
    while True:
        choice = main_menu()
        if choice == "1":
            run_general_test()
        elif choice == "2":
            run_sni_ip_test()
        elif choice == "0":
            print("Выход.")
            break
        else:
            print("Неверный выбор.")
