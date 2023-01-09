#!/usr/bin/env python3
#@CallMeRep
#Reverse IP With CIDR Ranger Support Type of list like
#google.com
#google.com/16
#https://google.com
#1.1.1.1
#1.1.1.1/16
#https://google.com/asumemek/kontolgoreng
#if you want add banned subdomains just input the subdomain. in banned_subdomains.txt
#if your list already have cidr just input the cidr "auto"
#if you dont want using cidr/range ip just input "0"

from threading import *
from threading import Thread
from queue import Queue
from socket import gethostbyname
import requests,re ,os, socket, os, urllib3, validators
from urllib.parse import urlparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from netaddr import IPNetwork


class Worker(Thread):
  def __init__(self, tasks):
      Thread.__init__(self)
      self.tasks = tasks
      self.daemon = True
      self.start()

  def run(self):
      while True:
          func, args, kargs = self.tasks.get()
          try: func(*args, **kargs)
          except Exception as e: print(e)
          self.tasks.task_done()

class ThreadPool:
  def __init__(self, num_threads):
      self.tasks = Queue(num_threads)
      for _ in range(num_threads): Worker(self.tasks)

  def add_task(self, func, *args, **kargs):
      self.tasks.put((func, args, kargs))

  def wait_completion(self):
      self.tasks.join()

class RevIP:
  def __init__(self, iplist):
    self.result = []
    self.ip = iplist
    self.cidr = input("cidr : ")
    self.thread = input("thread : ")

  def domainToIP(self):
    try:
      if self.ip.startswith( "http" ) or self.ip.startswith( "https" ): 
          self.ip = urlparse(self.ip).netloc
      if "/" in self.ip:
        if self.ip.endswith("/"): self.ip = self.ip[:-1]
        cidrf = re.findall("/(.*)", self.ip)
        if cidrf: self.cidr = cidrf[0]
        ipf = re.findall("(.*)/", self.ip)
        if ipf : self.ip = ipf[0]
      self.ip = socket.gethostbyname( self.ip )
    except:
      pass

    
    
  def rev(self,ips):
    head = {
        'Origin': 'https://www.ipaddress.com',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
        }
    data = {"host" : ips}
    try:
      r = requests.post("https://www.ipaddress.com/reverse-ip-lookup", data=data, headers=head, timeout=25, verify=False, allow_redirects=False).text
      if "We found no hostnames for " not in r:
        selector = re.findall("site\/(.*?)\"", r)
        print(f"ip : {ips} result: {len(selector)}")
        for results in selector:
          results = results.replace("\n", "").replace("\r", "")
          banSubdo = open('banned_subdomains.txt', 'r').read().splitlines()
          site = re.sub(r'[^A-Za-z0-9.\\-]','', results)
          for ban in banSubdo:site = site.replace(ban, "")
          if site not in self.result:
              self.result.append(site)
              open( "reversed.txt", "a" ).write( site + "\n" )
        return self.result
          
      else:
        print(f"ip : {ips} BAD-IPS [No-Results]")

    except Exception as e:
      
      print(e)
      pass

  def ranger(self, cidr):
    pool = ThreadPool(int(self.thread))
    print(f"( ip : {self.ip} cidr : {cidr} )")
    for ip in IPNetwork(f"{self.ip}/{cidr}"):
      pool.add_task( self.rev, ip )
    print(f"list: {self.ip}/{cidr} total result: {len(self.result)}")
    pool.wait_completion()

  def execute(self):
    pool2 = ThreadPool(int(self.thread))
    for url in self.ip:
      self.ip = url
      self.domainToIP()
      if self.cidr != "0" or self.cidr == "auto":
        self.ranger(self.cidr)
      else:
        pool2.add_task( self.rev, self.ip )
    pool2.wait_completion()
    print("Done Script")

if __name__ == '__main__':
  try:
    linux = 'clear'
    windows = 'cls'
    os.system([linux,windows][os.name == 'nt'])
  except:
    os.system(linux)
  try:
    print(f"""
    Simple Reverse IP Lookup ipaddress.com + Auto Range IP MultiThreaded 
    Input CIDR "0" to not using The Range IP
    Credits : @CallMeRep
    """)
    list = open(input("list : "), encoding="utf8" ).read().splitlines()
    RevIP(list).execute()
  except Exception as f:
    print(f)
    pass
