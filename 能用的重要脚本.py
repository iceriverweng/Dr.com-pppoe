# TESTED: u62R0 without 802.1x
import socket, struct, time
from hashlib import md5
import sys
import os

class ChallengeException (Exception):
  def __init__(self):
    pass

class LoginException (Exception):
  def __init__(self):
    pass
   
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 61440))

s.settimeout(3)
SALT = ''
# basic configuration
server = "172.19.0.200" # Auth server ip
username = "yzxq28022021"
password = "5238444"
host_name = "LIYUANYUAN"
host_os = "8089D"
host_ip = "172.20.97.28" # your ip, the server wouldn't check this, so it's a nonsense 
dhcp_server = "0.0.0.0"
mac = 0xb888e3051680
UNLIMITED_RETRY = True
EXCEPTION = False
DEBUG = False #log saves to file
LOG_PATH = '/var/log/drcom_client.log'


def log(*args, **kwargs):
    s = ' '.join(args)
    print s
    if DEBUG:
      with open(LOG_PATH,'a') as f:
          f.write(s + '\n')

def challenge(svr,ran):
    while True:
      t = struct.pack("<H", int(ran)%(0xFFFF))
      s.sendto("\x01\x02"+t+"\x09"+"\x00"*15, (svr, 61440))
      try:
        data, address = s.recvfrom(1024)
        log('[challenge] recv',data.encode('hex'))
      except:
        log('[challenge] timeout, retrying...')
        continue
        
      if address == (svr, 61440):
        break
      else:
        continue
    log('[DEBUG] challenge:\n' + data.encode('hex'))
    if data[0] != '\x02':
      raise ChallengeException
    log('[challenge] challenge packet sent.')
    return data[4:8]

def md5sum(s):
    m = md5()
    m.update(s)
    return m.digest()

def dump(n):
    s = '%x' % n
    if len(s) & 1:
        s = '0' + s
    return s.decode('hex')

def ror(md5, pwd):
    ret = ''
    for i in range(len(pwd)):
        x = ord(md5[i]) ^ ord(pwd[i])
        ret += chr(((x<<3)&0xFF) + (x>>5))
    return ret

def keep_alive_package_builder(number,random,tail,type=1,first=False):
    data = '\x07'+ chr(number) + '\x28\x00\x0b' + chr(type)
    if first :
      data += '\x0f\x27'
    else:
      data += '\x1f\x00'
    data += '\x2f\x12' + '\x00' * 6
    data += tail
    data += '\x00' * 4
    #data += struct.pack("!H",0xdc02)
    if type == 3:
      foo = ''.join([chr(int(i)) for i in host_ip.split('.')]) # host_ip
      #CRC
      # edited on 2014/5/12, filled zeros to checksum
      # crc = packet_CRC(data+foo)
      crc = '\x00' * 4
      #data += struct.pack("!I",crc) + foo + '\x00' * 8
      data += crc + foo + '\x00' * 8
    else: #packet type = 1
      data += '\x00' * 16
    return data

def packet_CRC(s):
    ret = 0
    for i in re.findall('..', s):
        ret ^= struct.unpack('>h', i)[0]
        ret &= 0xFFFF
    ret = ret * 0x2c7
    return ret

def keep_alive2(*args):
    #first keep_alive:
    #number = number (mod 7)
    #status = 1: first packet user sended
    #         2: first packet user recieved
    #         3: 2nd packet user sended
    #         4: 2nd packet user recieved
    #   Codes for test
    tail = ''
    packet = ''
    svr = server
    import random
    ran = random.randint(0,0xFFFF)
    ran += random.randint(1,10)   
    # 2014/10/15 add by latyas, maybe svr sends back a file packet
    svr_num = 0
    packet = keep_alive_package_builder(svr_num,dump(ran),'\x00'*4,1,True)
    while True:
        log('[keep-alive2] send1',packet.encode('hex'))
        s.sendto(packet, (svr, 61440))
        data, address = s.recvfrom(1024)
        if data[0] == '\x07' and data[2] == '\x28':
            break
        elif data[0] == '\x07' and data[2] == '\x10':
            log('[keep-alive2] recv file, resending..')
            svr_num = svr_num + 1
            packet = keep_alive_package_builder(svr_num,dump(ran),'\x00'*4,1,False)
        else:
            log('[keep-alive2] recv1/unexpected',data.encode('hex'))
    log('[keep-alive2] recv1',data.encode('hex'))
    
    ran += random.randint(1,10)   
    packet = keep_alive_package_builder(svr_num, dump(ran),'\x00'*4,1,False)
    log('[keep-alive2] send2',packet.encode('hex'))
    s.sendto(packet, (svr, 61440))
    while True:
        data, address = s.recvfrom(1024)
        if data[0] == '\x07':
            svr_num = svr_num + 1
            break
        else:
            log('[keep-alive2] recv2/unexpected',data.encode('hex'))
    log('[keep-alive2] recv2',data.encode('hex'))
    tail = data[16:20]
    

    ran += random.randint(1,10)   
    packet = keep_alive_package_builder(svr_num,dump(ran),tail,3,False)
    log('[keep-alive2] send3',packet.encode('hex'))
    s.sendto(packet, (svr, 61440))
    while True:
        data, address = s.recvfrom(1024)
        if data[0] == '\x07':
            svr_num = svr_num + 1
            break
        else:
            log('[keep-alive2] recv3/unexpected',data.encode('hex'))
    log('[keep-alive2] recv3',data.encode('hex'))
    tail = data[16:20]
    log("[keep-alive2] keep-alive2 loop was in daemon.")
    
    i = svr_num
    while True:
      try:
        ran += random.randint(1,10)   
        packet = keep_alive_package_builder(i,dump(ran),tail,1,False)
        #log('DEBUG: keep_alive2,packet 4\n',packet.encode('hex'))
        log('[keep_alive2] send',str(i),packet.encode('hex'))
        s.sendto(packet, (svr, 61440))
        data, address = s.recvfrom(1024)
        log('[keep_alive2] recv',data.encode('hex'))
        tail = data[16:20]
        #log('DEBUG: keep_alive2,packet 4 return\n',data.encode('hex'))
        
        ran += random.randint(1,10)   
        packet = keep_alive_package_builder(i+1,dump(ran),tail,3,False)
        #log('DEBUG: keep_alive2,packet 5\n',packet.encode('hex'))
        s.sendto(packet, (svr, 61440))
        log('[keep_alive2] send',str(i+1),packet.encode('hex'))
        data, address = s.recvfrom(1024)
        log('[keep_alive2] recv',data.encode('hex'))
        tail = data[16:20]
        #log('DEBUG: keep_alive2,packet 5 return\n',data.encode('hex'))
        i = (i+2) % 0xFF
        time.sleep(20)
        keep_alive1(*args)
      except:
        pass

    
import re
def checksum(s):
    ret = 1234
    for i in re.findall('....', s):
        ret ^= int(i[::-1].encode('hex'), 16)
    ret = (1968 * ret) & 0xffffffff
    return struct.pack('<I', ret)

def mkpkt(salt, usr, pwd, mac):
    data = '\x03\x01\x00'+chr(len(usr)+20)
    data += md5sum('\x03\x01'+salt+pwd)
    data += usr.ljust(36, '\x00')
    data += '\x20' #fixed unknow 1
    data += '\x02' #unknow 2
    data += dump(int(data[4:10].encode('hex'),16)^mac).rjust(6,'\x00') #mac xor md51
    data += md5sum("\x01" + pwd + salt + '\x00'*4) #md52
    data += '\x01' # number of ip
    #data += '\x0a\x1e\x16\x11' #your ip address1, 10.30.22.17
    data += ''.join([chr(int(i)) for i in host_ip.split('.')]) #x.x.x.x -> 
    data += '\00'*4 #your ipaddress 2
    data += '\00'*4 #your ipaddress 3
    data += '\00'*4 #your ipaddress 4
    data += md5sum(data + '\x14\x00\x07\x0b')[:8] #md53
    data += '\x01' #ipdog
    data += '\x00'*4 #delimeter
    data += host_name.ljust(32, '\x00')
    data += '\x08\x08\x08\x08' #primary dns: 8.8.8.8
    data += ''.join([chr(int(i)) for i in dhcp_server.split('.')]) #DHCP server
    data += '\x00\x00\x00\x00' #secondary dns:0.0.0.0
    data += '\x00' * 8 #delimeter
    data += '\x94\x00\x00\x00' # unknow
    data += '\x05\x00\x00\x00' # os major
    data += '\x01\x00\x00\x00' # os minor
    data += '\x28\x0a\x00\x00' # OS build
    data += '\x02\x00\x00\x00' #os unknown
    data += host_os.ljust(32,'\x00')
    data += '\x00' * 96
    #data += '\x01' + host_os.ljust(128, '\x00')
    #data += '\x0a\x00\x00'+chr(len(pwd)) # \0x0a represents version of client, algorithm: DRCOM_VER + 100
    #data += ror(md5sum('\x03\x01'+salt+pwd), pwd)
    data += '\x0a\x00'
    data += '\x02\x0c'
    data += checksum(data+'\x01\x26\x07\x11\x00\x00'+dump(mac))
    data += '\x00\x00' #delimeter
    data += dump(mac)
    data += '\x00' # auto logout / default: False
    data += '\x00' # broadcast mode / default : False
    data += '\xe9\x13' #unknown, filled numbers randomly =w=
    
    log('[mkpkt]',data.encode('hex'))
    return data

def login(usr, pwd, svr):
    import random
    global SALT
 
    i = 0
    while True:
        salt = challenge(svr,time.time()+random.randint(0xF,0xFF))
        SALT = salt
        packet = mkpkt(salt, usr, pwd, mac)
        log('[login] send',packet.encode('hex'))
        s.sendto(packet, (svr, 61440))
        data, address = s.recvfrom(1024)
        log('[login] recv',data.encode('hex'))
        log('[login] packet sent.')
        if address == (svr, 61440):
            if data[0] == '\x04':
              log('[login] loged in')
              break
            else:
              continue
        else:
            if i >= 5 and UNLIMITED_RETRY == False :
              log('[login] exception occured.')
              sys.exit(1)
            else:
              continue
            
    log('[login] login sent')
    #0.8 changed:
    return data[23:39]
    #return data[-22:-6]

def keep_alive1(salt,tail,pwd,svr):
    foo = struct.pack('!H',int(time.time())%0xFFFF)
    data = '\xff' + md5sum('\x03\x01'+salt+pwd) + '\x00\x00\x00'
    data += tail
    data += foo + '\x00\x00\x00\x00'
    log('[keep_alive1] send',data.encode('hex'))

    s.sendto(data, (svr, 61440))
    while True:
        data, address = s.recvfrom(1024)
        if data[0] == '\x07':
            break
        else:
            log('[keep-alive1]recv/not expected',data.encode('hex'))
    log('[keep-alive1] recv',data.encode('hex'))

def empty_socket_buffer():
#empty buffer for some fucking schools
    log('starting to empty socket buffer')
    try:
        while True:
            data, address = s.recvfrom(1024)
            log('recived sth unexcepted',data.encode('hex'))
            if s == '':
                break
    except:
        # get exception means it has done.
        log('exception in empty_socket_buffer')
        pass
    log('emptyed')

def main():
    log("auth svr:"+server+"\nusername:"+username+"\npassword:"+password+"\nmac:"+str(hex(mac)))
    while True:
      try:
        package_tail = login(username, password, server)
      except LoginException:
        continue
      log('package_tail',package_tail.encode('hex'))
      #keep_alive1 is fucking bullshit!
      empty_socket_buffer()
      keep_alive1(SALT,package_tail,password,server)
      #empty_socket_buffer()
      keep_alive2(SALT,package_tail,password,server)
if __name__ == "__main__":
    main()
