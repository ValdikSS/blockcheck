#!/usr/bin/env python3
# coding: utf-8
import argparse
import urllib.request
import urllib.parse
import urllib.error
import socket
import ssl
import sys
import dns.resolver
import dns.exception

# Configuration
dns_records_list = {"gelbooru.com": ['5.178.68.100'],
                    "e621.net": ['162.159.243.197', '162.159.244.197'],
                    "sukebei.nyaa.se": ['69.165.95.242'],
                    "2chru.net": ['162.159.251.219', '198.41.249.219']}

http_list = {'http://gelbooru.com/':
                 {'status': 200, 'lookfor': 'Hentai and Anime Imageboard', 'ip': '5.178.68.100'},
             'http://gelbooru.com/index.php?page=post&s=view&id=1989610':
                 {'status': 200, 'lookfor': 'Gelbooru- Image View', 'ip': '5.178.68.100'},
             'http://rule34.xxx/':
                 {'status': 200, 'lookfor': 'Rule 34', 'ip': '178.21.23.224'},
             'http://rule34.xxx/index.php?page=post&s=view&id=879177':
                 {'status': 200, 'lookfor': 'Rule 34', 'ip': '178.21.23.224'},
             'http://rutracker.org/forum/index.php':
                 {'status': 200, 'lookfor': 'static.rutracker.', 'ip': '195.82.146.214'},
            }

https_list = {'https://2chru.cafe/', 'https://e621.net/'}

dpi_list =   {'rutracker.org':
                {'host': 'rutracker.org', 'urn': '/forum/index.php',
                 'lookfor': 'static.rutracker.', 'ip': '195.82.146.214'},
              'gelbooru.com':
                {'host': 'gelbooru.com', 'urn': '/index.php?page=post&s=view&id=1989610',
                 'lookfor': 'Gelbooru- Image View', 'ip': '5.178.68.100'},
             }

proxy_addr = 'proxy.antizapret.prostovpn.org:3128'
google_dns = '8.8.4.4'
antizapret_dns = '195.123.209.38'
isup_server = 'isup.me'
isup_fmt = 'http://isup.me/{}'
disable_isup = False #If true, presume that all sites are available

# End configuration

try:
    import tkinter as tk
    import threading
    import queue
    tkusable = True

    class ThreadSafeConsole(tk.Text):
        def __init__(self, master, **options):
            tk.Text.__init__(self, master, **options)
            self.queue = queue.Queue()
            self.update_me()
        def write(self, line):
            self.queue.put(line)
        def clear(self):
            self.queue.put(None)
        def update_me(self):
            try:
                while 1:
                    line = self.queue.get_nowait()
                    if line is None:
                        self.delete(1.0, tk.END)
                    else:
                        self.insert(tk.END, str(line))
                    self.see(tk.END)
                    self.update_idletasks()
            except queue.Empty:
                pass
            self.after(100, self.update_me)

except ImportError:
    tkusable = False

    class ThreadSafeConsole():
        pass

def print(*args, **kwargs):
    if tkusable:
        for arg in args:
            text.write(str(arg))
        text.write("\n")
    else:
        __builtins__.print(*args, **kwargs)

def _get_a_record(site, dnsserver=None):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    if dnsserver:
        resolver.nameservers = [dnsserver]

    result = []
    while len(resolver.nameservers):
        try:
            for item in resolver.query(site).rrset.items:
                result.append(item.to_text())
            return result

        except dns.exception.Timeout:
            resolver.nameservers.remove(resolver.nameservers[0])

    # If all the requests failed
    return ""

def _get_a_records(sitelist, dnsserver=None):
    result = []
    for site in sitelist:
        try:
            for item in _get_a_record(site, dnsserver):
                result.append(item)
        except dns.resolver.NXDOMAIN:
            print("[!] Невозможно получить DNS-запись для домена {} (NXDOMAIN). Результаты могут быть неточными.".format(site))
        except dns.exception.DNSException:
            return ""

    return sorted(result)

def _decode_bytes(input_bytes):
    output = input_bytes
    try:
        output = input_bytes.decode(errors='replace')
    except:
        pass
    return output

def _get_url(url, proxy=None, ip=None):
    if ip:
        parsed_url = list(urllib.parse.urlsplit(url))
        host = parsed_url[1]
        parsed_url[1] = str(ip)
        newurl = urllib.parse.urlunsplit(parsed_url)
        req = urllib.request.Request(newurl)
        req.add_header('Host', host)
    else:
        req = urllib.request.Request(url)

    if proxy:
        req.set_proxy(proxy, 'http')
    
    req.add_header('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64; rv:30.0) Gecko/20100101 Firefox/30.0')

    try:
        opened = urllib.request.urlopen(req, timeout=15, cadefault=True)
        output = opened.read()
    except TypeError as e:
        if 'cadefault' in str(e):
            try:
                opened = urllib.request.urlopen(req, timeout=15, cafile="/etc/ssl/certs/ca-certificates.crt")
                output = opened.read()
            except FileNotFoundError:
                print("[☠] У вас слишком старая версия Python, которая не поддерживает проверку сертификатов.",
                      "Установите Python 3.3 или новее.")
                sys.exit(1)
    except ssl.CertificateError:
        return (-1, '')
    except (urllib.error.URLError, socket.error, socket.timeout) as e:
        if 'CERTIFICATE_VERIFY_FAILED' in str(e):
            return (-1, '')
        return (0, '')
    except Exception as e:
        print("[☠] Неизвестная ошибка:", repr(e))
        return (0, '')
    return (opened.status, _decode_bytes(output))

def _cut_str(string, begin, end):
    cut_begin = string.find(begin)
    if cut_begin == -1:
        return
    cut_end = string[cut_begin:].find(end)
    if cut_end == -1:
        return
    return string[cut_begin + len(begin):cut_begin + cut_end]

def _get_ip_and_isp():
    # Dirty and cheap
    try:
        data = _decode_bytes(urllib.request.urlopen("http://2ip.ru/", timeout=10).read())
        ip = _cut_str(data, '<big id="d_clip_button">', '</big>')
        isp = ' '.join(_cut_str(data, '"/isp/', '</a>').replace('">', '').split())
        if ip and isp:
            isp = urllib.parse.unquote(isp).replace('+', ' ')
            return (ip, isp)
    except:
        return

def _dpi_send(host, port, data, fragment_size=0, fragment_count=0):
    sock = socket.create_connection((host, port), 10)
    if fragment_count:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    try:
        for fragment in range(fragment_count):
            sock.sendall(data[:fragment_size].encode())
            data = data[fragment_size:]
        sock.sendall(data.encode())
        recvdata = sock.recv(8192)
        recv = recvdata
        while recvdata:
            recvdata = sock.recv(8192)
            recv += recvdata
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        sock.close()
    return _decode_bytes(recv)

def _dpi_build_tests(host, urn, ip, lookfor):
    dpi_built_list = \
        {'дополнительный пробел после GET':
                {'data': "GET  {} HTTP/1.0\r\n".format(urn) + \
                        "Host: {}\r\nConnection: close\r\n\r\n".format(host),
                'lookfor': lookfor, 'ip': ip,
                'fragment_size': 0, 'fragment_count': 0},
            'фрагментирование заголовка':
                {'data': "GET {} HTTP/1.0\r\n".format(urn) + \
                        "Host: {}\r\nConnection: close\r\n\r\n".format(host),
                'lookfor': lookfor, 'ip': ip,
                'fragment_size': 2, 'fragment_count': 6},
            'точка в конце домена':
                {'data': "GET {} HTTP/1.0\r\n".format(urn) + \
                        "Host: {}.\r\nConnection: close\r\n\r\n".format(host),
                'lookfor': lookfor, 'ip': ip,
                'fragment_size': 0, 'fragment_count': 0},
            'заголовок host вместо Host':
                {'data': "GET {} HTTP/1.0\r\n".format(urn) + \
                        "host: {}\r\nConnection: close\r\n\r\n".format(host),
                'lookfor': lookfor, 'ip': ip,
                'fragment_size': 0, 'fragment_count': 0},
            'перенос строки в заголовках в UNIX-стиле':
                {'data': "GET {} HTTP/1.0\n".format(urn) + \
                        "Host: {}\nConnection: close\n\n".format(host),
                'lookfor': lookfor, 'ip': ip,
                'fragment_size': 0, 'fragment_count': 0},
            'необычный порядок заголовков':
                {'data': "GET {} HTTP/1.0\r\n".format(urn) + \
                        "Connection: close\r\nHost: {}\r\n\r\n".format(host),
                'lookfor': lookfor, 'ip': ip,
                'fragment_size': 0, 'fragment_count': 0},
        }
    return dpi_built_list

def check_isup(page_url):
    """
    Check if the site is up using isup.me or whatever is set in
    `isup_fmt`. Return True if it's up, False if it's not, None
    if isup.me is itself unaccessible or there was an error while
    getting the response.

    `page_url` must be a string and presumed to be sanitized (but
    doesn't have to be the domain and nothing else, isup.me accepts
    full URLs)

    isup.me can't check HTTPS URL yet, so we return True for them.
    It's still useful to call check_isup even on HTTPS URLs for two
    reasons: because we may switch to a service that can can check them
    in the future and because check_isup will output a notification for
    the user.
    """
    #Note that isup.me doesn't use HTTPS and therefore the ISP can slip
    #false information (and if it gets blocked, the error page by the ISP can
    #happen to have the markers we look for). We should inform the user about
    #this possibility when showing results.
    if disable_isup:
        return True
    elif page_url.startswith("https://"):
        print("[☠] {} не поддерживает HTTPS, считаем, что сайт работает, "
              "а проблемы только у нас".format(isup_server))
        return True

    print("\tПроверяем доступность через {}".format(isup_server))

    url = isup_fmt.format(page_url)
    status, output = _get_url(url)
    if status in (0, -1):
        print("[⁇] Ошибка при соединении с {}".format(isup_server))
        return None
    elif status != 200:
        print("[⁇] Неожиданный ответ от {}, код {}".format(isup_server, status))
        return None
    elif output.find("It's just you") >= 0:
        print("[☠] Сайт доступен, проблемы только у нас")
        return True
    elif output.find("looks down from here") >= 0:
        print("[✗] Сайт недоступен, видимо, он не работает")
        return False
    else:
        print("[⁇] Не удалось распознать ответ от {}".format(isup_server))
        return None

def test_dns():
    sites = dns_records_list
    sites_list = list(sites.keys())
    
    print("[O] Тестируем DNS")
    print("[O] Получаем эталонные DNS с сервера")
    try:
        remote_dns = urllib.request.urlopen("http://blockcheck.antizapret.prostovpn.org/getdns.php",
            timeout=10).read()
        remote_dns = _decode_bytes(remote_dns).split()
        print("\tЭталонные адреса:\t\t", str(remote_dns))
    except:
        remote_dns = None
        print("[☠] Не удалось получить DNS с сервера, результаты могут быть неточными")

    resolved_default_dns = _get_a_records(sites_list)
    print("\tАдреса через системный DNS:\t", str(resolved_default_dns))
    resolved_google_dns = _get_a_records(sites_list, google_dns)
    if resolved_google_dns:
        print("\tАдреса через Google DNS:\t", str(resolved_google_dns))
    else:
        print("\tНе удалось подключиться к Google DNS")
    resolved_az_dns = _get_a_records(sites_list, antizapret_dns)
    if resolved_az_dns:
        print("\tАдреса через DNS AntiZapret:\t", str(resolved_az_dns))
    else:
        print("\tНе удалось подключиться к DNS AntiZapret")

    if not resolved_google_dns or not resolved_default_dns:
        return 4

    if (remote_dns):
        # Если получили IP с сервера, используем их
        dns_records = remote_dns
    else:
        dns_records = sorted([item for sublist in sites.values() for item in sublist])

    if resolved_default_dns == resolved_google_dns:
        if set(resolved_az_dns) == {antizapret_dns}:
            print("[✓] DNS-записи не подменяются")
            print("[✓] DNS не перенаправляется")
            return 0

        if resolved_default_dns == dns_records:
            print("[✓] DNS-записи не подменяются")
            print("[☠] DNS перенаправляется")
            return 1
        else:
            print("[☠] DNS-записи подменяются")
            print("[☠] DNS перенаправляется")
            return 2

    else:
        if resolved_google_dns == dns_records:
            print("[☠] DNS-записи подменяются")
            print("[✓] DNS не перенаправляется")
            return 3

    print("[?] Способ блокировки DNS определить не удалось")
    return 5

HTTP_ACCESS_NOBLOCKS = 0
HTTP_ACCESS_IPBLOCK = 1
HTTP_ACCESS_IPDPI = 2
HTTP_ACCESS_FULLDPI = 3

HTTP_ISUP_ALLUP = 0
HTTP_ISUP_SOMEDOWN = 1
HTTP_ISUP_ALLDOWN = 2
HTTP_ISUP_BROKEN = 3

def test_http_access(by_ip=False):
    """
    Test plain HTTP access and return two values:

    1. The result - one of the HTTP_ACCESS_* constants
    2. isup.me info - one of the HTTP_ISUP_* constants
    """
    sites = http_list
    proxy = proxy_addr

    print("[O] Тестируем HTTP")

    successes = 0
    successes_proxy = 0
    down = 0
    blocks = 0
    blocks_ambiguous = 0

    for site in sites:
        print("\tОткрываем ", site)
        result = _get_url(site, ip=sites[site].get('ip') if by_ip else None)
        if result[0] == sites[site]['status'] and result[1].find(sites[site]['lookfor']) != -1:
            print("[✓] Сайт открывается")
            successes += 1
        else:
            if result[0]  == sites[site]['status']:
                print("[☠] Получен неожиданный ответ, скорее всего, "
                      "страница-заглушка провайдера. Пробуем через прокси.")
            else:
                print("[☠] Сайт не открывается, пробуем через прокси")
            result_proxy = _get_url(site, proxy)
            if result_proxy[0] == sites[site]['status'] and result_proxy[1].find(sites[site]['lookfor']) != -1:
                print("[✓] Сайт открывается через прокси")
                successes_proxy += 1
            else:
                if result_proxy[0] == sites[site]['status']:
                    print("[☠] Получен неожиданный ответ, скорее всего, "
                          "страница-заглушка провайдера. Считаем заблокированным.")
                else:
                    print("[☠] Сайт не открывается через прокси")
                isup = check_isup(site)
                if isup is None:
                    blocks_ambiguous += 1
                elif isup:
                    blocks += 1
                else:
                    down += 1

    all_sites = len(sites)

    #Result without isup.me
    if successes == all_sites:
        result = HTTP_ACCESS_NOBLOCKS
    elif successes > 0 and successes + successes_proxy == all_sites:
        result = HTTP_ACCESS_IPDPI
    elif successes > 0:
        result = HTTP_ACCESS_FULLDPI
    else:
        result = HTTP_ACCESS_IPBLOCK

    #isup.me info
    if blocks_ambiguous > 0:
        isup = HTTP_ISUP_BROKEN
    elif down == all_sites:
        isup = HTTP_ISUP_ALLDOWN
    elif down > 0:
        isup = HTTP_ISUP_SOMEDOWN
    else:
        isup = HTTP_ISUP_ALLUP

    return result, isup

def test_https_cert():
    sites = https_list
    isup_problems = False

    print("[O] Тестируем HTTPS")

    siteresults = []
    for site in sites:
        print("\tОткрываем ", site)
        result = _get_url(site, None)
        if result[0] == -1:
            print("[☠] Сертификат подменяется")
            siteresults.append(False)
        elif result[0] < 200:
            print("[☠] Сайт не открывается")
            if check_isup(site):
                siteresults.append('no')
            else:
                isup_problems = True
        else:
            print("[✓] Сайт открывается")
            siteresults.append(True)
    if 'no' in siteresults:
        # Blocked
        return 2
    elif False in siteresults:
        # Wrong certificate
        return 1
    elif not isup_problems and all(siteresults):
        # No blocks
        return 0
    else:
        # Some sites are down or unknown result
        return 3

def test_dpi():
    print("[O] Тестируем обход DPI")

    dpiresults = []
    for dpisite in dpi_list:
        site = dpi_list[dpisite]
        dpi_built_tests = _dpi_build_tests(site['host'], site['urn'], site['ip'], site['lookfor'])
        for testname in dpi_built_tests:
            test = dpi_built_tests[testname]
            print("\tПробуем способ «{}» на {}".format(testname, dpisite))
            try:
                result = _dpi_send(test.get('ip'), 80, test.get('data'), test.get('fragment_size'), test.get('fragment_count'))
            except Exception as e:
                print("[☠] Ошибка:", repr(e))
            else:
                if result.split("\n")[0].find('200 ') != -1 and result.find(test['lookfor']) != -1:
                    print("[✓] Сайт открывается")
                    dpiresults.append(testname)
                elif result.split("\n")[0].find('200 ')  -1 and result.find(test['lookfor']) != -1:
                    print("[!] Сайт не открывается, обнаружен пассивный DPI!")
                    dpiresults.append('Passive DPI')
                else:
                    print("[☠] Сайт не открывается")
    return list(set(dpiresults))

def main():
    ip_isp = _get_ip_and_isp()
    if ip_isp:
        print("IP: {}, провайдер: {}".format(ip_isp[0], ip_isp[1]))
        print()
    dns = test_dns()
    print()
    http, http_isup = test_http_access((dns != 0))
    print()
    https = test_https_cert()
    print()
    dpi = '-'
    if http in (1, 2):
        dpi = test_dpi()
        print()
    print("[!] Результат:")
    if dns == 4:
        print("[⚠] Ваш провайдер блокирует чужие DNS-серверы.\n",
              "Вам следует использовать шифрованный канал до DNS-серверов, например, через VPN, Tor, " + \
              "HTTPS/Socks прокси или DNSCrypt.")
    elif dns == 3:
        print("[⚠] Ваш провайдер подменяет DNS-записи, но не перенаправляет чужие DNS-серверы на свой.\n",
              "Вам поможет смена DNS, например, на Яндекс.DNS 77.88.8.8 или Google DNS 8.8.8.8 и 8.8.4.4.")
    elif dns == 2:
        print("[⚠] Ваш провайдер подменяет DNS-записи и перенаправляет чужие DNS-серверы на свой.\n",
              "Вам следует использовать шифрованный канал до DNS-серверов, например, через VPN, Tor, " + \
              "HTTPS/Socks прокси или DNSCrypt.")
    elif dns == 1:
        print("[⚠] Ваш провайдер перенаправляет чужие DNS-серверы на свой, но не подменяет DNS-записи.\n",
              "Это несколько странно и часто встречается в мобильных сетях.\n",
              "Вам следует использовать шифрованный канал до DNS-серверов, например, через VPN, Tor, " + \
              "HTTPS/Socks прокси или DNSCrypt.")

    if https == 1:
        print("[⚠] Ваш провайдер подменяет HTTPS-сертификат на свой.")
    elif https == 2:
        print("[⚠] Ваш провайдер блокирует доступ к HTTPS-сайтам.")
    elif https == 3:
        print("[⚠] Доступ по HTTPS проверить не удалось, повторите тест позже.")

    if http_isup == HTTP_ISUP_BROKEN:
        print("[⚠] {0} даёт неожиданные ответы или недоступен. Рекомендуем " \
              "повторить тест, когда он начнёт работать. Возможно, эта " \
              "версия программы устарела. Возможно (но маловероятно), " \
              "что сам {0} уже занесён в чёрный список.".format(isup_server))
    elif http_isup == HTTP_ISUP_ALLDOWN:
        print("[⚠] Согласно {}, все проверяемые сайты сейчас не работают. " \
              "Убедитесь, что вы используете последнюю версию программы, и " \
              "повторите тест позже.".format(isup_server))
    elif http_isup == HTTP_ISUP_SOMEDOWN:
        print("[⚠] Согласно {}, часть проверяемых сайтов сейчас не работает. " \
              "Убедитесь, что вы используете последнюю версию программы, и " \
              "повторите тест позже.".format(isup_server))
    elif http_isup != HTTP_ISUP_ALLUP:
        print("[⚠] ВНУТРЕННЯЯ ОШИБКА ПРОГРАММЫ, http_isup = {}".format(http_isup))

    def print_http_result(symbol, message):
        if http_isup == HTTP_ISUP_ALLUP:
            print("{} {}".format(symbol, message))
        else:
            #ACHTUNG: translating this program into other languages
            #might be tricky. Not into English, though.
            print("{} Если проигнорировать {}, то {}" \
                .format(symbol, isup_server, message[0].lower() + message[1:]))

    if http == HTTP_ACCESS_IPBLOCK:
        print_http_result("[⚠]", "Ваш провайдер блокирует по IP-адресу. " \
                                 "Используйте любой способ обхода блокировок.")
    elif http == HTTP_ACCESS_FULLDPI:
        print_http_result("[⚠]", "У вашего провайдера \"полный\" DPI. Он " \
                                 "отслеживает ссылки даже внутри прокси, " \
                                 "поэтому вам следует использовать любое " \
                                 "шифрованное соединение, например, " \
                                 "VPN или Tor.")
    elif http == HTTP_ACCESS_IPDPI:
        print_http_result("[⚠]", "У вашего провайдера \"обычный\" DPI. " \
                                 "Вам поможет HTTPS/Socks прокси, VPN или Tor.")
    elif http_isup == HTTP_ISUP_ALLUP and http == HTTP_ACCESS_NOBLOCKS \
            and https == 0:
        print_http_result("[☺]", "Ваш провайдер не блокирует сайты.")

    _get_url('http://blockcheck.antizapret.prostovpn.org/index.php?dns=' + str(dns) + '&http=' + str(http) +
             '&https=' + str(https) + '&dpi=' + urllib.parse.quote(','.join(dpi)))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Определитель типа блокировки сайтов у провайдера.')
    parser.add_argument('--console', action='store_true', help='Консольный режим. Отключает Tkinter GUI.')
    parser.add_argument('--no-isup', action='store_true',
                            help='Не проверять доступность сайтов через {}' \
                                    .format(isup_server))
    args = parser.parse_args()

    if args.console:
        tkusable = False

    if args.no_isup:
        disable_isup = True

    if tkusable:
        root = tk.Tk()
        root.title("BlockCheck")
        text = ThreadSafeConsole(root)
        text.pack()
        threading.Thread(target=main).start()
        root.mainloop()
    else:
        try:
            main()
        except (KeyboardInterrupt, SystemExit):
            quit(1)
