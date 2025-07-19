#!/usr/bin/env python3
import requests
import ssl
import socket
import time
from urllib.parse import urlparse
import dns.resolver

# --- Настройки ---
SITES_FILENAME = "user_sites.txt"
TIMEOUT = 10  # Общий таймаут для сетевых операций

# Список сайтов для стандартного теста
DEFAULT_TEST_SUITE = [
    {"id": "YT", "provider": "YouTube", "url": "https://youtube.com"},
    {"id": "TG", "provider": "Telegram", "url": "https://web.telegram.org"},
    {"id": "RT", "provider": "RuTracker", "url": "https://rutracker.org"},
    # Сайт для теста DPI на разрыв соединения
    {"id": "DPI-16KB", "provider": "Hetzner", "url": "https://tcp1620-01.dubybot.live/1MB.bin"},
]

# --- Вспомогательные функции ---

def print_header(text):
    print("\n" + "=" * (len(text) + 4))
    print(f"| {text} |")
    print("=" * (len(text) + 4))

def load_user_sites():
    try:
        with open(SITES_FILENAME, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []

def save_user_sites(sites):
    with open(SITES_FILENAME, 'w') as f:
        for site in sites:
            f.write(site + '\n')

def add_user_site(url, sites_list):
    if url not in sites_list:
        sites_list.append(url)
        save_user_sites(sites_list)
        print(f"✅ Сайт {url} добавлен в ваш список.")
    else:
        print(f"ℹ️ Сайт {url} уже есть в вашем списке.")

# --- Функции отдельных тестов (без изменений) ---

def test_dns(hostname):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['1.1.1.1', '8.8.8.8']
    start_time = time.monotonic()
    try:
        answers = resolver.resolve(hostname)
        ip_address = answers[0].to_text()
        duration = time.monotonic() - start_time
        return f"OK ({ip_address})", f"{duration:.3f} с", ip_address
    except Exception as e:
        duration = time.monotonic() - start_time
        return f"Ошибка ({e.__class__.__name__})", f"{duration:.3f} с", None

def get_ip_location(ip_address):
    if not ip_address:
        return "N/A"
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=country,city", timeout=5)
        response.raise_for_status()
        data = response.json()
        return f"{data.get('country', '')}, {data.get('city', '')}"
    except requests.exceptions.RequestException:
        return "Не удалось определить"

def test_tls_version(host, ip, port, version_enum, version_str):
    if not ip:
        return "Пропуск (нет IP)"
    context = ssl.create_default_context()
    context.minimum_version = version_enum
    if version_str == "TLSv1.2":
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return "OK ✅"
    except Exception as e:
        return f"Blocked ❌ ({e.__class__.__name__})"

def test_ssl_handshake(host, ip, port):
    if not ip:
        return "Пропуск (нет IP)", "N/A"
    context = ssl.create_default_context()
    start_time = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                duration = time.monotonic() - start_time
                return "OK ✅", f"{duration:.3f} с"
    except ssl.SSLCertVerificationError:
        duration = time.monotonic() - start_time
        return "Подмена сертификата ❌", f"{duration:.3f} с"
    except Exception as e:
        duration = time.monotonic() - start_time
        return f"Ошибка ({e.__class__.__name__}) ❌", f"{duration:.3f} с"

def test_http_get(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'}
    try:
        response = requests.get(url, timeout=TIMEOUT, headers=headers)
        duration = response.elapsed.total_seconds()
        return f"OK ({response.status_code}) ✅", f"{duration:.3f} с"
    except requests.exceptions.RequestException as e:
        return f"Ошибка ({e.__class__.__name__}) ❌", "N/A"

def test_dpi_download(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        with requests.get(url, stream=True, timeout=TIMEOUT, headers=headers) as r:
            r.raise_for_status()
            total = 0
            for chunk in r.iter_content(chunk_size=8192):
                total += len(chunk)
                if total > 2 * 1024 * 1024:
                    return "Not detected ✅"
            if 16 * 1024 <= total <= 24 * 1024:
                return f"Detected❗️ ({total // 1024} KB)"
            return "Not detected ✅"
    except requests.exceptions.RequestException as e:
        return f"Detected❗️ ({e.__class__.__name__})"

def determine_verdict(results):
    if "Ошибка" in results["dns_status"]:
        return "DNS-блокировка ❗️"
    if "Подмена сертификата" in results["ssl_status"]:
        return "Подмена SSL (DPI/MITM) ❗️"
    if "Ошибка" in results["ssl_status"] and "Timeout" not in results["ssl_status"]:
        return "Блокировка по IP/SNI ❗️"
    if "Ошибка" in results["http_status"]:
        return "Блокировка по DPI (HTTP) ❗️"
    if "Detected" in results["dpi_download_status"]:
        return "DPI (разрыв при скачивании) ❗️"
    if "Timeout" in results["ssl_status"]:
        return "Блокировка 'black-hole' ❗️"
    return "Доступен ✅"

def run_full_test_on_url(url, url_info=""):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
    
    print(f"\n{url_info} ({hostname})")
    results = {}
    results["dns_status"], results["dns_time"], ip = test_dns(hostname)
    results["location"] = get_ip_location(ip)
    results["tls13_status"] = test_tls_version(hostname, ip, port, ssl.TLSVersion.TLSv1_3, "TLSv1.3")
    results["tls12_status"] = test_tls_version(hostname, ip, port, ssl.TLSVersion.TLSv1_2, "TLSv1.2")
    results["ssl_status"], results["ssl_time"] = test_ssl_handshake(hostname, ip, port)
    results["http_status"], results["http_time"] = test_http_get(url)
    results["dpi_download_status"] = test_dpi_download(url)
    results["verdict"] = determine_verdict(results)

    print(f'  DNS:       {results["dns_status"]}, {results["dns_time"]}')
    print(f'  Локация:   {results["location"]}')
    print(f'  TLS 1.3:   {results["tls13_status"]}')
    print(f'  TLS 1.2:   {results["tls12_status"]}')
    print(f'  SSL:       {results["ssl_status"]}, {results["ssl_time"]}')
    print(f'  HTTP:      {results["http_status"]}, {results["http_time"]}')
    print(f'  DPI (16KB):{results["dpi_download_status"]}')
    print(f'  Вердикт:   {results["verdict"]}')


# --- Функции для пунктов меню ---

def run_test_suite(suite, title):
    print_header(title)
    for i, item in enumerate(suite):
        if isinstance(item, dict):
            url = item["url"]
            info = f"[{item['id']}] {item['provider']}"
        else:
            url = item
            info = f"Сайт {i+1}/{len(suite)}"
        run_full_test_on_url(url, url_info=info)
        time.sleep(1)

def add_and_check_site(user_sites):
    print_header("Добавить и проверить новый сайт")
    new_url = input("Введите полный URL (например, https://example.com): ").strip()
    if not new_url:
        print("Ввод пуст, возврат в меню.")
        return
    if not new_url.startswith(('http://', 'https://')):
        new_url = 'https://' + new_url
    add_user_site(new_url, user_sites)
    run_full_test_on_url(new_url, url_info="Новый сайт")

def show_help():
    """Выводит справочную информацию о тестах и вердиктах."""
    print_header("Справка по результатам")
    help_text = """
Этот скрипт выполняет тесты с вашего компьютера для определения различных видов блокировок.

--- ОПИСАНИЕ ТЕСТОВ В ВЫВОДЕ ---

DNS:
  - Тест отправляет запросы к независимым публичным DNS-серверам (Cloudflare, Google).
  - "OK" означает, что IP-адрес успешно получен.
  - "Ошибка" говорит о невозможности получить IP. Это может быть как проблемой сети,
    так и признаком DNS-блокировки.

Локация:
  - Определяет страну и город, где предположительно находится сервер,
    на основе его IP-адреса через сервис ip-api.com.

TLS 1.3 / 1.2:
  - Проверяет возможность установить зашифрованное соединение с сервером, используя
    конкретную версию протокола TLS. Блокировка TLS 1.3 может указывать на то,
    что провайдер пытается понизить соединение до старой версии для анализа.

SSL:
  - Проверяет полное TLS-рукопожатие, включая проверку подлинности SSL-сертификата.
  - "OK" означает, что сертификат сайта подлинный и соединение установлено.
  - "Подмена сертификата" — явный признак атаки 'человек посередине' (MITM),
    часто используемой DPI для расшифровки и анализа HTTPS-трафика.
  - "Ошибка" (напр. ConnectionResetError) на этом этапе указывает на блокировку по IP
    или по имени сервера (SNI) на ранней стадии соединения.

HTTP:
  - После успешного TLS-соединения отправляется стандартный веб-запрос (HTTP GET).
  - "OK" c кодом 200-299 означает, что сервер успешно ответил.
  - "Ошибка" на этом этапе — классический признак DPI, который анализирует и
    блокирует трафик по его содержимому уже внутри "защищенного" канала.

DPI (16KB):
  - Специальный тест, который пытается скачать большой файл. Если загрузка обрывается
    на объеме около 16-24 КБ, это указывает на特定ный вид DPI-блокировки,
    разрывающей соединение после передачи небольшого объема данных.

--- ИНТЕРПРЕТАЦИЯ ИТОГОВЫХ ВЕРДИКТОВ ---

DNS-блокировка:
  - Не удалось получить IP-адрес домена. Возможно, домен не существует
    или его DNS-записи блокируются.

Блокировка по IP / SNI:
  - DNS-запрос успешен, но SSL-соединение было сброшено на самом раннем этапе.

Блокировка 'black-hole':
  - Запрос к серверу не завершился за отведенное время (таймаут). Трафик
    к заблокированному ресурсу просто отбрасывается без ответа.

Подмена SSL (DPI/MITM):
  - Соединение установлено, но SSL-сертификат не является доверенным.
    Явный признак атаки 'человек посередине' (MITM).

Блокировка по DPI (HTTP):
  - DNS и SSL-соединение прошли успешно, но последующий HTTP-запрос
    внутри защищенного канала был заблокирован.

DPI (разрыв при скачивании):
  - Выявлен специфический тип DPI, рвущий соединение при попытке скачать файл.

Доступен:
  - Все основные тесты (DNS, SSL, HTTP) прошли успешно.
"""
    print(help_text)


# --- Главная функция и меню ---

def main_menu():
    print_header("DPI & Connectivity Tester (v4.1)")
    print("1. Полная проверка по стандартному списку сайтов")
    print("2. Полная проверка сайтов из вашего списка")
    print("3. Добавить и проверить новый сайт")
    print("4. Справка по результатам")
    print("0. Выход")
    return input("\nВыберите пункт меню: ").strip()

def main():
    user_sites = load_user_sites()
    while True:
        choice = main_menu()
        if choice == '1':
            run_test_suite(DEFAULT_TEST_SUITE, "Проверка по стандартному списку")
        elif choice == '2':
            if user_sites:
                run_test_suite(user_sites, "Проверка сайтов из вашего списка")
            else:
                print("Ваш список сайтов пуст. Добавьте сайт через пункт 3.")
        elif choice == '3':
            add_and_check_site(user_sites)
        elif choice == '4':
            show_help()
        elif choice == '0':
            print("Выход.")
            break
        else:
            print("Неверный выбор.")
        
        input("\n--- Нажмите Enter для возврата в меню ---")

if __name__ == "__main__":
    main()
