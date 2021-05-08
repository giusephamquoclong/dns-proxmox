import requests
import re
import unidecode
import urllib3
import json
import sys
from colorama import Fore 
from termcolor import colored 
from pprint import PrettyPrinter, pprint
from operator import add, itemgetter, attrgetter
from pygments import highlight, lexers, formatters

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


ip_proxmox='10.200.104.3'

def get_cookie(ip):
    url=f"https://{ip}:8006/api2/json/access/ticket"
    headers = {'Content-Type': 'application/x-www-form-urlencoded',
               'Content-Type': 'application/json',
               'Connection':'keep-alive'}
    login = {'username':'root@pam',
             'password':'Abc@1234'}
    resp = requests.post(url,headers=headers,data=json.dumps(login),verify=False)
    # data=cookie.json()
    # print(data['response'])
    cookie=json.loads(resp.text)
    # print(cookie["data"]["ticket"])
    return cookie["data"]["ticket"]

def get_CSRF(ip):
    url = f"https://{ip}:8006/api2/json/access/ticket"
    headers = {'Content-Type': 'application/x-www-form-urlencoded',
               'Content-Type': 'application/json',
               'Connection': 'keep-alive'}
    login = {'username': 'root@pam',
             'password': 'Abc@1234'}
    resp = requests.post(url, headers=headers,
                         data=json.dumps(login), verify=False)
    # data=cookie.json()
    # print(data['response'])
    cookie = json.loads(resp.text)
    # print(cookie["data"]["ticket"])
    return cookie["data"]["CSRFPreventionToken"]

def find_vm(ip, vm_name):
    vms = getallVM(ip)
    allvm = []
    for vm in vms:
        if re.search(vm_name, vm['name-vm']):
            allvm.append(vm)
    allvm = sorted(allvm, key=itemgetter('id', 'name-vm'))
    return allvm


def getallVM(ip):
    cookie='PVEAuthCookie='+str(get_cookie(ip))
    # print(cookie)
    url = f"https://{ip}:8006/api2/json/cluster/resources"
    headers = {'Content-Type': 'application/x-www-form-urlencoded',
               'Content-Type': 'application/json',
               'Connection': 'keep-alive',
               'Cookie':cookie}
    parameter={'type':'vm'}
    resp = requests.get(url, headers=headers,params=parameter,
                          verify=False)
    datas=json.loads(resp.text)
    # pprint(datas)
    vm = []
    # pprint(datas)
    for data in datas["data"]:
        if data['status']=='running':
            nodename = data["node"]
            id = data['vmid']
            name = data["name"]
            vm.append({"node-name": nodename, "id": id, "name-vm": name})
    
    vm = sorted(vm, key=itemgetter('id', 'name-vm'))
    return vm

def getall_vm_running(ip):
    cookie = 'PVEAuthCookie='+str(get_cookie(ip))
    # print(cookie)
    url = f"https://{ip}:8006/api2/json/cluster/resources"
    headers = {'Content-Type': 'application/x-www-form-urlencoded',
               'Content-Type': 'application/json',
               'Connection': 'keep-alive',
               'Cookie': cookie}
    parameter = {'type': 'vm'}
    resp = requests.get(url, headers=headers, params=parameter,
                        verify=False)
    datas = json.loads(resp.text)
    vm = []
    # pprint(datas)
    for data in datas["data"]:
        if data['status']=='running':
            nodename = data["node"]
            id = data['vmid']
            name = data["name"]
            vm.append({"node-name": nodename, "id": id, "name-vm": name})
    vm = sorted(vm, key=itemgetter('id', 'node-name'))
    return vm

def getipvm(ip, vm):
    nodename = find_vm(ip, vm)[0]['node-name']
    vmid = find_vm(ip, vm)[0]['id']
    cookie = 'PVEAuthCookie='+str(get_cookie(ip))
    # print(cookie)
    url = f"https://{ip}:8006/api2/json/nodes/{nodename}/qemu/{vmid}/agent/network-get-interfaces"
    headers = {'Content-Type': 'application/x-www-form-urlencoded',
               'Content-Type': 'application/json',
               'Connection': 'keep-alive',
               'Cookie': cookie}
    resp = requests.get(url, headers=headers, verify=False)
    datas = json.loads(resp.text)
    if datas["data"] == None:
        return "No Guest Agent configured"
    else:
        for data in datas["data"]["result"]:
            if data["name"] == "eth0" or data["name"] == "ens192" or data["name"] == "ens18":
                for ipadd in data["ip-addresses"]:
                    if ipadd["ip-address-type"] == "ipv4":
                        return ipadd["ip-address"]

def check_exist_rule(ip, id, sport, node):
    cookie = 'PVEAuthCookie='+str(get_cookie(ip))
    CSRF = str(get_CSRF(ip))
    # print(cookie)
    url = f"https://{ip}:8006/api2/json/nodes/{node}/qemu/{id}/firewall/rules"
    print(url)
    headers = {'Content-Type': 'application/x-www-form-urlencoded',
               'Content-Type': 'application/json',
               'Connection': 'keep-alive',
               'Cookie': cookie,
               'CSRFPreventionToken': CSRF}
    resp = requests.get(url, headers=headers,
                        verify=False)
    datas = json.loads(resp.text)
    for data in datas["data"]:
        if (("dport" and "sport") in data) and (data["sport"] == sport and data["type"] == "out"):
            return True
        if (("dport" and "sport") in data) and (data["sport"] == sport and data["type"] == "in"):
            return True


def add_firewall_vm(ip, idmaymo, idmayketnoi, portmaycanmo, protocol):
    
    ipmaycanmo=getipvm(ip,idmaymo)
    ipmayketnoi=getipvm(ip,idmayketnoi)
    checkmayhost = bool(find_vm(ip, idmaymo))
    checkmayketnoi = bool(find_vm(ip, idmayketnoi))
    if checkmayhost==True and idmayketnoi=="":
        mayhost = find_vm(ip, idmaymo)
        vmid_mayhost = mayhost[0]['id']
        nodename_mayhost = mayhost[0]['node-name']
        cookie = 'PVEAuthCookie='+str(get_cookie(ip))
        CSRF = str(get_CSRF(ip))
        print(cookie)
        url1 = f"https://{ip}:8006/api2/json/nodes/{nodename_mayhost}/qemu/{vmid_mayhost}/firewall/rules"
        # print(url1)
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Content-Type': 'application/json',
                   'Connection': 'keep-alive',
                   'Cookie': cookie,
                   'CSRFPreventionToken': CSRF}
        rule_out = {'action': 'ACCEPT',
                    'enable': 1,
                    'type': "out",
                    'sport': portmaycanmo,
                    'dport': "32768:65535",
                    'proto': protocol}
        rule_in = {'action': 'ACCEPT',
                   'enable': 1,
                   'type': "in",
                   'sport': "32768:65535",
                   'dport': portmaycanmo,
                   'proto': protocol}
        rule_in1=[]
        rule_out1=[]
        resp1 = requests.post(url1, headers=headers,
                                data=json.dumps(rule_in), verify=False)
        resp2 = requests.post(url1, headers=headers,
                            data=json.dumps(rule_out), verify=False)
        
    elif checkmayhost == True and checkmayketnoi == True:
        mayhost = find_vm(ip, idmaymo)
        vmid_mayhost = mayhost[0]['id']
        nodename_mayhost = mayhost[0]['node-name']
        cookie = 'PVEAuthCookie='+str(get_cookie(ip))
        CSRF = str(get_CSRF(ip))
        print(cookie)
        url1 = f"https://{ip}:8006/api2/json/nodes/{nodename_mayhost}/qemu/{vmid_mayhost}/firewall/rules"
        # print(url1)
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Content-Type': 'application/json',
                   'Connection': 'keep-alive',
                   'Cookie': cookie,
                   'CSRFPreventionToken': CSRF}
        rule_out = {'action': 'ACCEPT',
                    'enable': 1,
                    'type': "out",
                    'sport': portmaycanmo,
                    'dport': "32768:65535",
                    'dest': ipmayketnoi,
                    'proto': protocol}
        rule_in = {'action': 'ACCEPT',
                   'enable': 1,
                   'type': "in",
                   'sport': "32768:65535",
                   'dport': portmaycanmo,
                   'source': ipmayketnoi,
                   'proto': protocol}
        rule_in1=[]
        rule_out1=[]
        if check_exist_rule(ip,vmid_mayhost,portmaycanmo,nodename_mayhost) == True:
            resp = requests.get(url1, headers=headers,
                                verify=False)
            datas = json.loads(resp.text)
            for data in datas["data"]:
                if (("dport" and"sport") in data) and (data["sport"] == portmaycanmo and data["type"] == "out"):
                    dest = data["dest"]
                    pos = data["pos"]
                    rule_out1 = {'pos': pos,
                                 'dest': f'{dest},{ipmayketnoi}'}
                    url1=f"https://{ip}:8006/api2/json/nodes/{nodename_mayhost}/qemu/{vmid_mayhost}/firewall/rules/{pos}"
                    resp1 = requests.put(url1, headers=headers,
                              data=json.dumps(rule_out1), verify=False)
                if (("dport" and"sport") in data) and (data["dport"] == portmaycanmo and data["type"] == "in"):
                    source = data["source"]
                    pos = data["pos"]
                    rule_in1 = {'pos': pos,
                               'source': f'{source},{ipmayketnoi}'}
                    url1=f"https://{ip}:8006/api2/json/nodes/{nodename_mayhost}/qemu/{vmid_mayhost}/firewall/rules/{pos}"
                    resp2 = requests.put(url1, headers=headers,
                              data=json.dumps(rule_in1), verify=False)
            pprint(rule_in1)
            pprint(rule_out1)
        else :
            resp1 = requests.post(url1, headers=headers,
                                data=json.dumps(rule_in), verify=False)
            resp2 = requests.post(url1, headers=headers,
                                data=json.dumps(rule_out), verify=False)

        url2 = f"https://{ip}:8006/api2/json/nodes/{nodename_mayhost}/qemu/{vmid_mayhost}/firewall/options"
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Content-Type': 'application/json',
                   'Connection': 'keep-alive',
                   'Cookie': cookie,
                   'CSRFPreventionToken': CSRF}
        parameter = {'policy_in': 'DROP',
                     'policy_out': 'DROP',
                     'enable': 1}
        resp3 = requests.put(url2,headers=headers,data=json.dumps(parameter), verify=False)


        # # ------------------------------------------------------------------------------
        mayketnoi = find_vm(ip, idmayketnoi)
        vmid_mayketnoi = mayketnoi[0]['id']
        nodename_mayketnoi = mayketnoi[0]['node-name']
        url1 = f"https://{ip}:8006/api2/json/nodes/{nodename_mayketnoi}/qemu/{vmid_mayketnoi}/firewall/rules"
        print(url1)
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Content-Type': 'application/json',
                   'Connection': 'keep-alive',
                   'Cookie': cookie,
                   'CSRFPreventionToken': CSRF}
        rule_out = {'action': 'ACCEPT',
                    'enable': 1,
                    'type': "out",
                    'sport': "32768:65535",
                    'dport': portmaycanmo,
                    'dest': ipmaycanmo,
                    'proto': protocol}
        rule_in = {'action': 'ACCEPT',
                   'enable': 1,
                   'type': "in",
                   'sport': portmaycanmo,
                   'dport': "32768:65535",
                   'source': ipmaycanmo,
                   'proto': protocol}
        
        rule_in1=[]
        rule_out1=[]
        
        if check_exist_rule(ip,vmid_mayketnoi,portmaycanmo,nodename_mayketnoi) == True:
            resp = requests.get(url1, headers=headers,
                                verify=False)
            datas = json.loads(resp.text)
            for data in datas["data"]:
                if (("dport" and"sport") in data) and (data["sport"] == portmaycanmo and data["type"] == "in"):
                    # pprint(data)
                    source = data["source"]
                    pos = data["pos"]
                    rule_out1 = {'pos': pos,
                                 'source': f'{source},{ipmaycanmo}'}
                    url1=f"https://{ip}:8006/api2/json/nodes/{nodename_mayketnoi}/qemu/{vmid_mayketnoi}/firewall/rules/{pos}"
                    resp1 = requests.put(url1, headers=headers,
                              data=json.dumps(rule_out1), verify=False)
                if (("dport" and"sport") in data) and (data["dport"] == portmaycanmo and data["type"] == "out"):
                    # pprint(data)
                    dest = data["dest"]
                    pos = data["pos"]
                    rule_in1 = {'pos': pos,
                               'source': f'{dest},{ipmaycanmo}'}
                    url1=f"https://{ip}:8006/api2/json/nodes/{nodename_mayketnoi}/qemu/{vmid_mayketnoi}/firewall/rules/{pos}"
                    resp2 = requests.put(url1, headers=headers,
                              data=json.dumps(rule_in1), verify=False)
            pprint(rule_in1)
            pprint(rule_out1)
        else :
            resp1 = requests.post(url1, headers=headers,
                                data=json.dumps(rule_in), verify=False)
            resp2 = requests.post(url1, headers=headers,
                                data=json.dumps(rule_out), verify=False)
        
        
        pprint(resp1.text)
        pprint(resp2.text)

        url2 = f"https://{ip}:8006/api2/json/nodes/{nodename_mayketnoi}/qemu/{vmid_mayketnoi}/firewall/options"
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Content-Type': 'application/json',
                   'Connection': 'keep-alive',
                   'Cookie': cookie,
                   'CSRFPreventionToken': CSRF}
        parameter = {'policy_in': 'DROP',
                     'policy_out': 'DROP',
                     'enable': 1}
        resp3 = requests.put(url2,headers=headers,data=json.dumps(parameter), verify=False)
        # pprint(resp3.text)

if __name__ == '__main__':
    pprint(find_vm(ip_proxmox,"idb"))
    # add_firewall_vm(ip_proxmox,"3cx-idb","","23456","tcp")