#!/usr/bin/env python3
# coding: utf-8
import argparse
import urllib.request
import urllib.parse
import urllib.error
import socket
import ssl
import dns.resolver
import dns.exception

# Configuration
dns_records_list = {"gelbooru.com": ['5.178.68.100'],
                    "lostfilm.tv": ['5.199.162.26'],
                    "sukebei.nyaa.se": ['69.165.95.242'],
                    "2chru.net": ['162.159.251.219', '198.41.249.219']}

http_list = {'http://gelbooru.com/':
                 {'status': 200, 'lookfor': 'Hentai and Anime Imageboard', 'ip': '5.178.68.100'},
             'http://gelbooru.com/index.php?page=post&s=view&id=1989610':
                 {'status': 200, 'lookfor': 'Gelbooru- Image View', 'ip': '208.100.25.82'},
             'http://www.skidows.net/':
                 {'status': 200, 'lookfor': 'dle_root', 'ip': '188.190.119.202'},
             'http://www.skidows.net/video/nashe-filmy/19440-batalon-2015.html':
                 {'status': 200, 'lookfor': 'dle_root', 'ip': '188.190.119.202'},
             'http://sukebei.nyaa.se/':
                 {'status': 200, 'lookfor': 'A BitTorrent community', 'ip': '69.165.95.242'},
             'http://sukebei.nyaa.se/?page=view&tid=395631':
                 {'status': 200, 'lookfor': 'A BitTorrent community', 'ip': '69.165.95.242'},
            }

https_list = {'https://2chru.net/'}

proxy_addr = 'proxy.antizapret.prostovpn.org:3128'
google_dns = '8.8.4.4'
antizapret_dns = '107.150.11.192'

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
        output = opened.readall()
    except (urllib.error.URLError, socket.error, socket.timeout): # we do not expect ssl.CertificateError here
        return (0, '')
    return (opened.status, str(output))

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
        if resolved_default_dns == dns_records:
            if resolved_az_dns == resolved_google_dns:
                print("[✓] DNS записи не подменяются")
                print("[☠] DNS перенаправляется")
                return 1
            else:
                print("[✓] DNS записи не подменяются")
                print("[✓] DNS не перенаправляется")
                return 0
        else:
            print("[☠] DNS записи подменяются")
            print("[☠] DNS перенаправляется")
            return 2
    else:
        if resolved_google_dns == dns_records:
            print("[☠] DNS записи подменяются")
            print("[✓] DNS не перенаправляется")
            return 3
        elif set(resolved_az_dns) != {antizapret_dns}:
            print("[☠] DNS записи подменяются")
            print("[☠] DNS перенаправляется")
            return 2
        else:
            print("[?] Способ блокировки DNS определить не удалось")
            return 4

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
        try:
            result = _get_url(site, None)
            if result[0] < 200:
                print("[☠] Сайт не открывается")
            else:
                print("[✓] Сайт открывается")
                siteresults.append(True)
        except ssl.CertificateError:
            print("[☠] Сертификат подменяется")
            siteresults.append(False)

    if all(siteresults):
        # No blocks
        return 0
    elif any(siteresults):
        # Blocked
        return 1
    else:
        # Unknown result
        return 2

def main():
    dns = test_dns()
    print()
    if dns == 0:
        http = test_http_access(False)
    else:
        http = test_http_access(True)
    print()
    https = test_https_cert()
    print()
    print("[!] Результат:")
    if dns == 4:
        print("[⚠] Ваш провайдер блокирует чужие DNS-серверы.\n",
              "Вам следует использовать шифрованный канал до DNS-серверов, например, через VPN, Tor или " + \
              "HTTPS/Socks прокси.")
    elif dns == 3:
        print("[⚠] Ваш провайдер подменяет DNS-записи, но не перенаправляет чужие DNS-серверы на свой.\n",
              "Вам поможет смена DNS, например, на Яндекс.DNS 77.88.8.8 или Google DNS 8.8.8.8 и 8.8.4.4.")
    elif dns == 2:
        print("[⚠] Ваш провайдер подменяет DNS-записи и перенаправляет чужие DNS-серверы на свой.\n",
              "Вам следует использовать шифрованный канал до DNS-серверов, например, через VPN, Tor или " + \
              "HTTPS/Socks прокси.")
    elif dns == 1:
        print("[⚠] Ваш провайдер перенаправляет чужие DNS-серверы на свой, но не подменяет DNS-записи.\n",
              "Это несколько странно и часто встречается в мобильных сетях.\n",
              "Вам следует использовать шифрованный канал до DNS-серверов, например, через VPN, Tor или " + \
              "HTTPS/Socks прокси.")

    if https == 1:
        print("[⚠] Ваш провайдер лезет в HTTPS.")

    if http == 3:
        print("[⚠] Ваш провайдер блокирует по IP-адресу.\n",
              "Используйте любой способ обхода блокировок.")
    elif http == 2:
        print("[⚠] У вашего провайдера \"полный\" DPI. Он отслеживает ссылки даже внутри прокси, поэтому вам следует " + \
              "использовать любое шифрованное соединение, например, VPN или Tor.")
    elif http == 1:
        print("[⚠] У вашего провайдера \"обычный\" DPI.\n",
              "Вам поможет HTTPS/Socks прокси, VPN или Tor.")
    elif http == 0:
        print("[☺] Ваш провайдер не блокирует сайты.")

    _get_url('http://blockcheck.antizapret.prostovpn.org/index.php?dns=' + str(dns) + '&http=' + str(http) + '&https=' + str(https))

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
