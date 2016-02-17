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
            }

https_list = {'https://2chru.cafe/', 'https://e621.net/'}

dpi_list =  {'дополнительный пробел после GET':
                 {'data': "GET  /index.php?page=post&s=view&id=1989610 HTTP/1.0\r\n" + \
                         "Host: gelbooru.com\r\nConnection: close\r\n\r\n",
                  'lookfor': 'Gelbooru- Image View', 'ip': '5.178.68.100',
                  'fragment_size': 0, 'fragment_count': 0},
             'фрагментирование заголовка':
                 {'data': "GET /index.php?page=post&s=view&id=1989610 HTTP/1.0\r\n" + \
                         "Host: gelbooru.com\r\nConnection: close\r\n\r\n",
                  'lookfor': 'Gelbooru- Image View', 'ip': '5.178.68.100',
                  'fragment_size': 2, 'fragment_count': 6},
             'точка в конце домена':
                 {'data': "GET  /index.php?page=post&s=view&id=1989610 HTTP/1.0\r\n" + \
                         "Host: gelbooru.com.\r\nConnection: close\r\n\r\n",
                  'lookfor': 'Gelbooru- Image View', 'ip': '5.178.68.100',
                  'fragment_size': 0, 'fragment_count': 0},
             'заголовок host вместо Host':
                 {'data': "GET  /index.php?page=post&s=view&id=1989610 HTTP/1.0\r\n" + \
                         "host: gelbooru.com\r\nConnection: close\r\n\r\n",
                  'lookfor': 'Gelbooru- Image View', 'ip': '5.178.68.100',
                  'fragment_size': 0, 'fragment_count': 0},
             'перенос строки в заголовках в UNIX-стиле':
                 {'data': "GET  /index.php?page=post&s=view&id=1989610 HTTP/1.0\n" + \
                         "Host: gelbooru.com\nConnection: close\n\n",
                  'lookfor': 'Gelbooru- Image View', 'ip': '5.178.68.100',
                  'fragment_size': 0, 'fragment_count': 0},
            }

proxy_addr = 'proxy.antizapret.prostovpn.org:3128'
google_dns = '8.8.4.4'
antizapret_dns = '195.123.209.38'
isup_server = 'isup.me'
isup_fmt = 'http://isup.me/{}'

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
    except (urllib.error.URLError, socket.error, socket.timeout) as e:
        if 'CERTIFICATE_VERIFY_FAILED' in str(e):
            return (-1, '')
        return (0, '')
    return (opened.status, str(output))

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
        data = urllib.request.urlopen("http://2ip.ru/", timeout=10).read().decode()
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
    return recv.decode()

def check_isup(page_url):
    """
    Check if the site is up using isup.me or whatever is set in
    `isup_fmt`. Return True if it's up, False if it's not, None
    if isup.me is itself unaccessible or there was an error while
    getting the response.

    `page_url` must be a string and presumed to be sanitized (but
    doesn't have to be the domain and nothing else, isup.me accepts
    full URLs)
    """
    #Note that isup.me doesn't use HTTPS and therefore the ISP can slip
    #false information (and if it gets blocked, the error page by the ISP can
    #happen to have the markers we look for). But we're disregarding this
    #possibility for now.
    print("Проверяю доступность через {}".format(isup_server))

    url = isup_fmt.format(page_url)
    status, output = _get_url(url)
    if status in (0, -1):
        print("[⁇] Ошибка при соединении с {}".format(isup_server))
        return None
    elif status != 200:
        print("[⁇] Неожиданный ответ от {}, код {}".format(isup_server, status))
        return None
    elif output.find("It\\'s just you") >= 0:
        print("[☠] Сайт доступен, проблемы только у нас")
        return True
    elif output.find("looks down from here") >= 0:
        print("[⁇] Сайт недоступен, видимо, он лежит")
        return False
    else:
        print("[⁇] Ответ от {} не удалось распознать".format(isup_server))
        return None

def test_dns():
    sites = dns_records_list
    sites_list = list(sites.keys())
    
    print("[O] Тестируем DNS")
    print("[O] Получаем эталонные DNS с сервера")
    try:
        remote_dns = urllib.request.urlopen("http://blockcheck.antizapret.prostovpn.org/getdns.php",
            timeout=10).read()
        remote_dns = remote_dns.decode('utf-8').split()
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

def test_http_access(by_ip=False):
    sites = http_list
    proxy = proxy_addr

    print("[O] Тестируем HTTP")

    siteresults = []
    for site in sites:
        print("\tОткрываем ", site)
        result = _get_url(site, ip=sites[site].get('ip') if by_ip else None)
        if result[0] == sites[site]['status'] and result[1].find(sites[site]['lookfor']) != -1:
            print("[✓] Сайт открывается")
            siteresults.append(True)
        else:
            print("[☠] Сайт не открывается")
            siteresults.append(False)

    siteresults_proxy = []
    for site in sites:
        print("\tОткрываем через прокси ", site)
        result_proxy = _get_url(site, proxy)
        if result_proxy[0] == sites[site]['status'] and result_proxy[1].find(sites[site]['lookfor']) != -1:
            print("[✓] Сайт открывается")
            siteresults_proxy.append(True)
        else:
            print("[☠] Сайт не открывается")
            siteresults_proxy.append(False)

    if all(siteresults):
        # No blocks
        return 0
    elif any(siteresults) and all(siteresults_proxy):
        # IP-DPI
        return 1
    elif any(siteresults) and any(siteresults_proxy):
        # Full-DPI
        return 2
    else:
        # IP
        return 3

def test_https_cert():
    sites = https_list

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
            siteresults.append('no')
        else:
            print("[✓] Сайт открывается")
            siteresults.append(True)
    if 'no' in siteresults:
        # Blocked
        return 2
    elif all(siteresults):
        # No blocks
        return 0
    elif any(siteresults):
        # Wrong certificate
        return 1
    else:
        # Unknown result
        return 3

def test_dpi():
    print("[O] Тестируем обход DPI")

    dpiresults = []
    for testname in dpi_list:
        test = dpi_list[testname]
        print("\tПробуем способ: " + testname)
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
    #Check Python version
    if sys.version_info[0] == 3 and sys.version_info[1] < 3:
        print("ОШИБКА! Слишком старая версия Python: у вас {}.{}, требуется",
              "3.3 или новее".format(sys.version_info[0], sys.version_info[1]))
        return

    ip_isp = _get_ip_and_isp()
    if ip_isp:
        print("IP: {}, провайдер: {}".format(ip_isp[0], ip_isp[1]))
        print()
    dns = test_dns()
    print()
    if dns == 0:
        http = test_http_access(False)
    else:
        http = test_http_access(True)
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
    if https == 2:
        print("[⚠] Ваш провайдер блокирует доступ к HTTPS-сайтам.")

    if http == 3:
        print("[⚠] Ваш провайдер блокирует по IP-адресу.\n",
              "Используйте любой способ обхода блокировок.")
    elif http == 2:
        print("[⚠] У вашего провайдера \"полный\" DPI. Он отслеживает ссылки даже внутри прокси, поэтому вам следует " + \
              "использовать любое шифрованное соединение, например, VPN или Tor.")
    elif http == 1:
        print("[⚠] У вашего провайдера \"обычный\" DPI.\n",
              "Вам поможет HTTPS/Socks прокси, VPN или Tor.")
    elif http == 0 and https == 0:
        print("[☺] Ваш провайдер не блокирует сайты.")

    _get_url('http://blockcheck.antizapret.prostovpn.org/index.php?dns=' + str(dns) + '&http=' + str(http) +
             '&https=' + str(https) + '&dpi=' + urllib.parse.quote(','.join(dpi)))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Определитель типа блокировки сайтов у провайдера.')
    parser.add_argument('--console', action='store_true', help='Консольный режим. Отключает Tkinter GUI.')
    args = parser.parse_args()
    if args.console:
        tkusable = False

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
