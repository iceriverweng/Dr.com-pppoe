#start p version project
import socket, struct, time,sys,urllib2,random,re,uuid
from hashlib import md5

CONF = "d:/drcom.txt"

class ChallengeException (Exception):
  def __init__(self):
    pass

class loginException (Exception):
  def __init__(self):
    pass
	

#this part is basic support form d version----------------------------------------------------
def try_socket():
#sometimes cannot get the port
	global s,salt
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.bind(("0.0.0.0", 61440))
		s.settimeout(3)
	except:
		print ".",
		time.sleep(0.5)
		print ".",
		time.sleep(0.5)
		print "."
		time.sleep(0.5)
		print "...reopen"
		time.sleep(10)
		sys.exit(0)
	else:
		SALT= ''

def dump(n):
    s = '%x' % n
    if len(s) & 1:
        s = '0' + s
    return s.decode('hex')

def md5sum(s):
    m = md5()
    m.update(s)
    return m.digest()

	
	
	
#this a main functuon and start keep_n---------------------------------------------------------
#keep_n mean normal cert process

def keep_alive_package_builder(number,random,tail,type=1,first=False):
    data = '\x07'+ chr(number) + '\x28\x00\x0b' + chr(type)
    if first :
      data += '\x0f\x27'
    else:
      data += '\xdc\02'
    data += '\x2f\x12' + '\x00' * 6
    data += tail
    data += '\x00' * 4
    #data += struct.pack("!H",0xdc02)
    if type == 3:
      foo = ''.join([chr(int(i)) for i in host_ip.split('.')]) # host_ip
	#use double keep in main to keep online .Ice
      crc = '\x00' * 4
      #data += struct.pack("!I",crc) + foo + '\x00' * 8
      data += crc + foo + '\x00' * 8
    else: #packet type = 1
      data += '\x00' * 16
    return data

def keep_alive1(salt,tail,pwd,svr):
    foo = struct.pack('!H',int(time.time())%0xFFFF)
    data = '\xff' + md5sum('\x03\x01'+salt+pwd) + '\x00\x00\x00'
    data += tail
    data += foo + '\x00\x00\x00\x00'
    print '[keep_alive1] send'#data.encode('hex'))

    s.sendto(data, (svr, 61440))
    while True:
        data, address = s.recvfrom(1024)
        if data[0] == '\x07':
            break
        else:
            print '[keep-alive1]recv/not expected'#data.encode('hex')
			
def keep_alive2(*args):
    tail = ''
    packet = ''
    svr = server
    ran = random.randint(0,0xFFFF)
    ran += random.randint(1,10)   
    
    packet = keep_alive_package_builder(0,dump(ran),'\x00'*4,1,True)
    #packet = keep_alive_package_builder(0,dump(ran),dump(ran)+'\x22\x06',1,True)
    print '[keep-alive2] send1'#packet.encode('hex')
    while True:
        s.sendto(packet, (svr, 61440))
        data, address = s.recvfrom(1024)
        if data.startswith('\x07'):
            break
        else:
		continue
            #print '[keep-alive2] recv/unexpected',data.encode('hex')
    #print '[keep-alive2] recv1',data.encode('hex')
    
    ran += random.randint(1,10)   
    packet = keep_alive_package_builder(1,dump(ran),'\x00'*4,1,False)
    #print '[keep-alive2] send2',packet.encode('hex')
    s.sendto(packet, (svr, 61440))
    while True:
        data, address = s.recvfrom(1024)
        if data[0] == '\x07':
            break
    #print '[keep-alive2] recv2',data.encode('hex')
    tail = data[16:20]
    

    ran += random.randint(1,10)   
    packet = keep_alive_package_builder(2,dump(ran),tail,3,False)
    #print '[keep-alive2] send3',packet.encode('hex')
    s.sendto(packet, (svr, 61440))
    while True:
        data, address = s.recvfrom(1024)
        if data[0] == '\x07':
            break
    #print '[keep-alive2] recv3',data.encode('hex')
    tail = data[16:20]
    print "[keep-alive] keep-alive loop was in daemon."
    i = 3

    while True:
      try:
		keep_alive1(SALT,package_tail,password,server)
		print '[keep-alive2] send'
		ran += random.randint(1,10)   
		packet = keep_alive_package_builder(i,dump(ran),tail,1,False)
		#print('DEBUG: keep_alive2,packet 4\n',packet.encode('hex'))
		#print '[keep_alive2] send',str(i),packet.encode('hex')
		s.sendto(packet, (svr, 61440))
		data, address = s.recvfrom(1024)
		#print '[keep_alive2] recv',data.encode('hex')
		tail = data[16:20]
		#print('DEBUG: keep_alive2,packet 4 return\n',data.encode('hex'))
        
		ran += random.randint(1,10)   
		packet = keep_alive_package_builder(i+1,dump(ran),tail,3,False)
		#print('DEBUG: keep_alive2,packet 5\n',packet.encode('hex'))
		s.sendto(packet, (svr, 61440))
		#print('[keep_alive2] send',str(i+1),packet.encode('hex'))
		data, address = s.recvfrom(1024)
		#print('[keep_alive2] recv',data.encode('hex'))
		tail = data[16:20]
		#print('DEBUG: keep_alive2,packet 5 return\n',data.encode('hex'))
		i = (i+2) % 0xFF
		time.sleep(20)
      except:
        pass

if __name__ == "__main__":
	global server,username,password,host_name,host_os,dhcp_server,mac,hexip,host_ip
	execfile(CONF, globals())
	try_socket()
	keep_alive2()
	
	
	
		

