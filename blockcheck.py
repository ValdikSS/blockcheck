#!/usr/bin/python3
# coding: utf-8
import urllib.request
import dns.resolver
try:
    import tkinter as tk
    import threading
    tkusable = True
except ImportError:
    tkusable = False

def print(*args, **kwargs):
    if tkusable:
        #text.insert(tk.END, "%s %s" % (args))
        for arg in args:
            text.insert(tk.END, str(arg) + " ")
        text.insert(tk.END, "\n")
        text.see(tk.END)
        text.update()
        #__builtins__.print(*args)
    else:
        __builtins__.print(*args, **kwargs)

def _get_a_records(sitelist, dnsserver = None):
    resolver = dns.resolver.Resolver()
    
    if dnsserver:
        resolver.nameservers = [dnsserver]

    result = []
    for site in sitelist:
        for item in resolver.query(site).rrset.items:
            result.append(str(item))

    return result

def _get_url(url, proxy = None):
    req = urllib.request.Request(url)

    if proxy:
        req.set_proxy(proxy, 'http')
    
    req.add_header('User-Agent', 'Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11')

    opened = urllib.request.urlopen(req)
    return (opened.status, str(opened.readall()))

def test_dns():
    sites = ["grani.ru"]
    
    print("[O] Тестируем DNS")
    resolved_default_dns = _get_a_records(sites)
    print("\tАдреса через системный DNS:\t", resolved_default_dns)
    resolved_google_dns = _get_a_records(sites, '8.8.4.4')
    print("\tАдреса через Google DNS:\t", resolved_google_dns)
    resolved_az_dns = _get_a_records(sites, '107.150.11.192')
    print("\tАдреса через DNS AntiZapret:\t", resolved_az_dns)

    if resolved_default_dns == resolved_google_dns:
        if resolved_az_dns != resolved_default_dns:
            print("[✓] DNS записи не подменяются")
            print("[✓] DNS не перенаправляется")
            return 0
        elif resolved_az_dns == resolved_default_dns:
            print("[☠] DNS записи подменяются")
            print("[☠] DNS перенаправляется")
            return 1
    else:
        print("[☠] DNS записи подменяются")
        print("[✓] DNS не перенаправляется")
        return 2

def test_http_access():
    sites = {'http://grani.ru/':
                 {'status': 200, 'lookfor': 'href="/wiki/Blocked/" class="loud"'},
             'http://www.lostfilm.tv/details.php?id=4141':
                 {'status': 200, 'lookfor': 'Achilles Heel'},
             'http://www.lostfilm.tv/':
                 {'status': 200, 'lookfor': 'LostFilm.TV.'},
            }
    proxy = 'proxy.antizapret.prostovpn.org:3128'
    
    print("[O] Тестируем HTTP")

    siteresults = []
    for site in sites:
        print("\tОткрываем", site)
        result = _get_url(site)
        if result[0] == sites[site]['status'] and result[1].find(sites[site]['lookfor']) != -1:
            print("[✓] Сайт открывается")
            siteresults.append(True)
        else:
            print("[☠] Сайт не открывается")
            siteresults.append(False)

    siteresults_proxy = []
    for site in sites:
        print("\tОткрываем через прокси", site)
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
    http = test_http_access()
    print()
    print("[!] Результат:")
    if dns == 2:
        print("Ваш провайдер подменяет DNS-записи, но не перенаправляет чужие DNS-серверы на свой.\n",
              "Вам поможет смена DNS, например, на Яндекс.DNS 77.88.8.8 или Google DNS 8.8.8.8 и 8.8.4.4.")
        return
    if dns == 1:
        print("Ваш провайдер подменяет DNS-записи и перенаправляет чужие DNS-серверы на свой.\n",
              "Вам следует использовать непрямой канал до DNS-серверов, например, через VPN, Tor или",
              "HTTPS/Socks прокси.")
        return
    if http == 2:
        print("У вашего провайдера \"полный\" DPI. Он отслеживает ссылки даже внутри прокси, поэтому вам следует",
              "использовать любое шифрованное соединение, например, VPN или Tor.")
        return
    if http == 1:
        print("У вашего провайдер \"обычный\" DPI.\n",
              "Вам поможет HTTPS/Socks прокси, VPN или Tor.")
        return
    if http == 3:
        print("Ваш провайдер блокирует по IP-адресу.\n",
              "Используйте любой способ обхода блокировок.")
        return
    if http == 0 and dns == 0:
        print("Ваш провайдер не блокирует сайты.")
        return
    print("Тип блокировки определить не удалось.")

if __name__ == "__main__":
    if tkusable:
        root = tk.Tk()
        root.title("BlockCheck")
        text = tk.Text(root)
        text.pack()
        threading.Thread(target=main).start()
        root.mainloop()
    else:
        main()
