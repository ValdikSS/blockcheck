#!/usr/bin/env python3
# coding: utf-8
import argparse
import itertools
import urllib.request
import urllib.parse
import dns.resolver

# Configuration
dns_records_list = {"gelbooru.com": ['208.100.25.82'],
                    "lostfilm.tv": ['162.159.249.129', '162.159.250.129'],
                    "sukebei.nyaa.se": ['188.95.48.66'],
                    "2chru.net": ['162.159.251.219', '198.41.249.219']}

http_list = {'http://gelbooru.com/':
                 {'status': 200, 'lookfor': 'Hentai and Anime Imageboard', 'ip': '208.100.25.82'},
             'http://gelbooru.com/index.php?page=post&s=view&id=1989610':
                 {'status': 200, 'lookfor': 'Gelbooru- Image View', 'ip': '208.100.25.82'},
             'http://www.lostfilm.tv/':
                 {'status': 200, 'lookfor': 'LostFilm.TV.', 'ip': '162.159.250.129'},
             'http://www.lostfilm.tv/details.php?id=4141':
                 {'status': 200, 'lookfor': 'Achilles Heel', 'ip': '162.159.250.129'},
             'http://sukebei.nyaa.se/':
                 {'status': 200, 'lookfor': 'A BitTorrent community', 'ip': '188.95.48.66'},
             'http://sukebei.nyaa.se/?page=view&tid=395631':
                 {'status': 200, 'lookfor': 'A BitTorrent community', 'ip': '188.95.48.66'},
            }

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

def _get_a_records(sitelist, dnsserver = None):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    
    if dnsserver:
        resolver.nameservers = [dnsserver]

    result = []
    for site in sitelist:
        try:
            for item in resolver.query(site).rrset.items:
                result.append(item.to_text())
        except:
            return ""

    return sorted(result)

def _get_url(url, proxy = None, ip = None):
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
        opened = urllib.request.urlopen(req, timeout=15)
    except:
        return (0, '')
    return (opened.status, str(opened.readall()))

def test_dns():
    sites = dns_records_list
    sites_list = list(sites.keys())
    sites_values = list(itertools.chain(*sites.values()))
    
    print("[O] Тестируем DNS")
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

    # далее рассматриваем каждый возможный случай -- желательно по отдельности
    
    if not resolved_google_dns or not resolved_az_dns:
        # это самый простой случай провайдерской DNS-блокировки
        return 4
    
    if set(resolved_default_dns) != set(sites_values) \
            and set(resolved_google_dns) == set(sites_values):
        # это самый простой случай провайдерской DNS-подмены
        print("[☠] DNS записи подменяются")
        print("[✓] DNS не перенаправляется")
        return 3
    
    if set(resolved_google_dns) != set(sites_values):
        print("[☠] DNS перенаправляется")
        # XXX
        #       мы выявили что DNS перенаправляется, но вдруг это не является проблемой?
        #       смотрим чуть глубже:
        if set(resolved_default_dns) == set(sites_values):
            print("[✓] Но системный DNS работает корректно")
            return 5
        else:
            print("[☠] DNS записи подменяются")
            return 2
    
    if set(resolved_az_dns) == set(sites_values) \
            and set(resolved_google_dns) == set(sites_values):
        # XXX
        #       это хитрый случай, так как ``resolved_az_dns`` должен содержать другое
        print("[✓] DNS записи не подменяются")
        print("[☠] DNS перенаправляется")
        return 1
    
    # лишь в последнюю очередь -- если ранее косяков не было выявлено --
    #   то наконец мы можем перейти к проверке самого благосостоятельного варианта
    
    if set(resolved_default_dns) == set(sites_values) \
            and set(resolved_google_dns) == set(sites_values):
        # самое лучшее что может быть: все равны!
        print("[✓] DNS записи не подменяются")
        print("[✓] DNS не перенаправляется")
        return 0
    
    # иначе (если интерпретатор дошёл до этого места в коде) --
    #   мы не можем сделать какой-бы-то-ни-было вывод.
    #   в итоге взвратится None и утилита не сделает ни какого вывода (так как 0 != None)

def test_http_access(by_ip = False):
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

def main():
    dns = test_dns()
    print()
    if dns == 0:
        http = test_http_access(False)
    else:
        http = test_http_access(True)
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

    _get_url('http://blockcheck.antizapret.prostovpn.org/index.php?dns=' + str(dns) + '&http=' + str(http))

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
        main()
