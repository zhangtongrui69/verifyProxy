from selenium import webdriver
import urllib
import time
import threading
import queue
import random
# from bs4 import BeautifulSoup
import socket
from struct import *
import pymysql
import requests

# import bs4
# import codecs

# target_url="http://www.google.com/"  # visit this website while verify the proxy
# target_string='Google Search'		# the returned html text should contain this string
target_url = "http://www.baidu.com/"  # visit this website while verify the proxy
target_string = '030173'		# the returned html text should contain this string
target_timeout = 30                   # the response time should be less than target_timeout seconds
                                    # then we consider this is a valid proxy


dbpassword='localhost'
# items in q is a list: ip, port, protocol, country
qproxy = queue.Queue()
qsocks = queue.Queue()
qout = queue.Queue()

baiduIp = '103.235.46.39'
baiduPort = 80

def isSocks4(host, port, soc):
    ipaddr = socket.inet_aton(baiduIp)
    packet4 = b"\x04\x01" + pack(">H", baiduPort) + ipaddr + b"\x00"
    soc.sendall(packet4)
    data = soc.recv(8)
    if (len(data) < 2):
        # Null response
        return False
    if data[0] != 0:
        # Bad data
        return False
    if data[1] != 0x5A:
        # Server returned an error
        return False
    return True


def isSocks5(host, port, soc):
    soc.sendall(b"\x05\x01\x00")
    data = soc.recv(2)
    if (len(data) < 2):
        # Null response
        return False
    if data[0] != 0x5:
        # Not socks5
        return False
    if data[1] != 0x0:
        # Requires authentication
        return False
    return True


def getSocksVersion(host, port):
    try:
        proxy = host + ':' + str(port)
        if port < 0 or port > 65536:
            print("Invalid: " + proxy)
            return 0
    except:
        print("Invalid: " + proxy)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((host, port))
        if (isSocks4(host, port, s)):
            s.close()
            return 5
        elif (isSocks5(host, port, s)):
            s.close()
            return 4
        else:
            print("Not a SOCKS: " + host + ':' + str(port))
            s.close()
            return 0
    except socket.timeout:
        print(": Timeout")
        s.close()
        return 0
    except socket.error:
        print("Connection refused: " + host + ':' + str(port))
        s.close()
        return 0



class ThreadSocksChecker(threading.Thread):
    def __init__(self, queue, timeout, idx):
        self.timeout = timeout
        self.q = queue
        self.index = idx
        threading.Thread.__init__(self)

    def isSocks4(self, host, port, soc):
        ipaddr = socket.inet_aton(host)
        packet4 = b"\x04\x01"+pack(">H",port) + ipaddr + b"\x00"
        soc.sendall(packet4)
        data = soc.recv(8)
        if(len(data)<2):
            # Null response
            return False
        if data[0] != 0x0:
            # Bad data
            return False
        if data[1] != 0x5A:
            # Server returned an error
            return False
        return True

    def isSocks5(self, host, port, soc):
        soc.sendall(b"\x05\x01\x00")
        data = soc.recv(2)
        if(len(data)<2):
            # Null response
            return False
        if data[0] != 0x5:
            # Not socks5
            return False
        if data[1] != 0x0:
            # Requires authentication
            return False
        return True

    def getSocksVersion(self, host, port):
        try:
            proxy = host+':'+str(port)
            if port < 0 or port > 65536:
                print("Invalid: " + proxy)
                return 0
        except:
            print("Invalid: " + proxy)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((host, port))
            if(self.isSocks4(host, port, s)):
                s.close()
                return 4
            elif(self.isSocks5(host, port, s)):
                s.close()
                return 5
            else:
                print("Not a SOCKS: " + host +':'+ str(port))
                s.close()
                return 0
        except socket.timeout:
            print(self.index, ": Timeout")
            s.close()
            return 0
        except socket.error:
            print(self.index, "Connection refused: " + host + ':'+str(port))
            s.close()
            return 0
    def run(self):
        while True:
            try:
                proxy = self.q.get(False)
                version = self.getSocksVersion(proxy[0], proxy[1])
                if version == 5 or version == 4:
                    print("Working: " + proxy[0], proxy[1])
                    a = [proxy[0], proxy[1], 1, 500]
                    qout.put(a)
                else:
                    a = [proxy[0], proxy[1], 0, 0]
                    qout.put(a)
            except queue.Empty:
                print('thread ', self.index,': quit')
                break


class thread_check_one_proxy(threading.Thread):
    def __init__(self, que, index):
        threading.Thread.__init__(self)
        self.index = index
        self.q = que
        proxydata = ()
        return

    def check_one_proxy(self, ip,port):
        global target_url,target_string,target_timeout

        print('thread '+str(self.index)+': processing '+str(ip)+':'+str(port))
        url=target_url
        checkstr=target_string
        timeout=target_timeout
        ip=ip.strip()
        proxy=ip+':'+str(port)
        proxies = {'http':'http://'+proxy+'/'}
        opener = urllib.request.FancyURLopener(proxies)
        opener.addheaders = [
            ('User-agent','Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)')
            ]
        t1=time.time()

        if (url.find("?")==-1):
            url=url+'?rnd='+str(random.random())
        else:
            url=url+'&rnd='+str(random.random())

        try:
            f = opener.open(url)
            s= str(f.read())
            pos=s.find(checkstr)
        except Exception as ee:
            print('thread ', self.index,':', ee)
            pos=-1
            pass
        t2=time.time()
        timeused=t2-t1
        if (timeused<timeout and pos>0):
            active=1
        else:
            active=0
        qout.put([ip,port, active, timeused])
        print('thread ',(self.index),' ',qout.qsize(),' active:: ',active," ",ip,':',port,'--',int(timeused))
        return

    def run(self):
        while True:
            try:
                proxydata = self.q.get(False)
                self.check_one_proxy(proxydata[0], proxydata[1])
            except queue.Empty:
                print(self.index,': quit')
                break
            except Exception as ee:
                print(self.index,': Exception ',ee)
                break
        return


def createProxyListTable():
    cnx = pymysql.connect(user='root', password=dbpassword,
                          host='127.0.0.1',
                          database='mypythondb')
    cursor = cnx.cursor()

    querys = ["create table `freeproxy` (`idx` int(10) unsigned not null auto_increment, " \
            "ip varchar(45) not null, port int(10) unsigned not null, country varchar(45), "\
            "protocol varchar(45), primary key(`idx`))",
            "ALTER TABLE `mypythondb`.`freeproxy` ADD UNIQUE INDEX `index1` (`ip` ASC, `port` ASC)",
            "alter table `mypythondb`.`freeproxy` add column `active` boolean default false",
            "alter table `mypythondb`.`freeproxy` add column `speed` int default 0",
            "alter table `mypythondb`.`freeproxy` add column `time_added` timestamp default '0000-00-00 00:00:00'",
            "alter table `mypythondb`.`freeproxy` add column `time_verified` timestamp default '0000-00-00 00:00:00'"]

    for query in querys:
        try:
            cursor.execute(query)
        except Exception as e:
            print(e)
    cursor.close()
    cnx.close()


if __name__ == '__main__':
    createProxyListTable()

    cnx = pymysql.connect(user='root', password=dbpassword,
                          host='127.0.0.1',
                          database='mypythondb')
    cursor = cnx.cursor()
    cursor.execute("select ip, port, protocol from `mypythondb`.`freeproxy`")
    for (ip, port, protocol) in cursor:
        a=[ip, port]
        if 'sock' in protocol or 'SOCK' in protocol or 'Sock' in protocol:
            qsocks.put(a)
        else:
            qproxy.put(a)

    print('http proxy: ', qproxy.qsize(), ' socks proxy: ', qsocks.qsize())
    threads = []
    threadcount = 50

    for i in range(threadcount):
        t = ThreadSocksChecker(qsocks, 500, i)
        threads.insert(i, t)

    for thread in threads:
        thread.start()

    while True:
        try:
            a = qout.get(True, 300)
            update = "update `mypythondb`.`freeproxy` set active="
            update+= str(a[2])
            update+= ", speed="
            update+= str(a[3])
            update+= ", time_verified=NOW() where ip='"+a[0]+"' and port="+str(a[1])
            cursor.execute(update)
            cnx.commit()
        except queue.Empty:
            break

    cursor.close()
    cnx.close()

    alive = 0
    for thread in threads:
        if thread.is_alive():
            alive+= 1
    print('living thread: ', alive)
    quit(alive)
