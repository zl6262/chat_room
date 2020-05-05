# -*- coding:utf-8 -*-
import socket
import select
import json
import threading
import time
import datetime
import random
import re
import struct
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
from hashlib import md5
import base64

header_len = 4

global ALL_SOCK
USER_FILE = None            #保存账号的文件
USER_INFO = {}              #已经登陆的账号的临时信息 {用户名:{'GROUP':所在小组, 'fd':连接句柄}}
GROUP_INFO = {}              #已经创建的小组的临时信息 {小组名:{'cnt':成员个数, 'member':{所有成员名字}}
ALL_SOCK = []                 #select所监听的socket队列
PRIVATE_PEM=None
PUBLIC_PEM=None
CIPHER=None
random_generator=None
random_str=None
pubkey=''
cipher={}
# 生成AESkey
def gene_aeskey():        
    global random_str
    randomlength=10
    random_str = ''
    base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789'
    length = len(base_str) - 1
    for i in range(randomlength):
        random_str += base_str[random.randint(0, length)]
    return

def send_aeskey(user):    #发送aeskey  用rsa加密
    global USER_INFO
    global CIPHER
    global random_str
    global random_generator        #rsa key
    print("001")
    encode_randomstr=base64.b64encode(cipher[user].encrypt(random_str.encode("UTF-8"))).decode()     #此刻的aeskey是已经被客户端发送的rsa加密给加密过的
    data={'type':99,'key':encode_randomstr}
    print("002")
    send_fd_set = {USER_INFO[user]['fd']}
    print('003')
    message = json.dumps(data)
    print("111")
    send_message(message, send_fd_set, 0)
    return

def get_pubkey(data):
    print("Received Pubkey from client!")
    global cipher
    user=data['user']
    rsakey=RSA.importKey(data['pubkey'])
    cipher[user]=Cipher_pkcs1_v1_5.new(rsakey)
    send_aeskey(user)
    



#打开账户信息文件，文件保存了"账号"，"密码(经过hash加密)"，"在线时长"
def init():
    global USER_FILE
    global PRIVATE_PEM
    global PUBLIC_PEM
    global CIPHER
    global random_generator
    USER_FILE = open('user.txt', 'r+')
    # 伪随机数生成器
    random_generator = Random.new().read
    # rsa算法生成实例
    rsa = RSA.generate(1024, random_generator)
    # master的秘钥对的生成
    PRIVATE_PEM= rsa.exportKey()
    PUBLIC_PEM = rsa.publickey().exportKey()
    CIPHER = Cipher_pkcs1_v1_5.new(rsa)
    gene_aeskey()
    return

#账号断连时，将对应的账号信息从内存清空，将本次在线时长添加进总时长里保存
def clear_sock(fd):
    global USER_INFO
    global USER_FILE
    global ALL_SOCK
    user = ''
    group = ''
    ALL_SOCK.remove(fd)
    try:
        fd.close()
    except:
        pass
    for temp in USER_INFO:
        if fd == USER_INFO[temp]['fd']:
            group = USER_INFO[temp]['group']
            user = temp
            break
    if '' == user:
        return
    else:
        online_time = time.time() - USER_INFO[user]['login_time']       #下线时间减去上线时间
        USER_FILE.seek(0, 0)
        lines = USER_FILE.readlines()
        USER_FILE.truncate()
        USER_FILE.seek(0, 0)
        for line in lines:
            if '' == line:
                continue
            try:
                info = eval(line)
            except:
                continue
            if info['user'] == user:
                info['time'] = info['time'] + online_time
                line = str(info)+'\n'
            USER_FILE.write(line)
        USER_FILE.flush()
        USER_INFO.pop(user)
        if '' != group:
            GROUP_INFO[group]['member'].remove(user)
            GROUP_INFO[group]['cnt'] = GROUP_INFO[group]['cnt'] - 1
            if 0 == GROUP_INFO[group]['cnt']:
                del GROUP_INFO[group]
    return

#发送报文的接口，传入"要发送的内容"，"要发送的目的的fd组成的集合"以及"需要排除的fd"
def send_message(message, send_fd_set, src_fd):
    length = len(message)
    message = struct.pack('i', length) + message.encode()
    for target in send_fd_set:
        if target != src_fd:
            try:
                target.sendall(message)
            except:
                clear_sock(target)

#生成盐值
def create_salt():
    return Random.new().read(8)

#生成加盐后的MD5值
def create_md5(pwd,salt):  
    md5_obj = md5()  
    md5_obj.update(pwd + salt)  
    return md5_obj.hexdigest()

#处理发来的注册报文
#在文件中如果找到对应账号，则返回报文errorcode:1,成功返回errorcode:0
def register(data, src_fd):
    global USER_FILE
    global CIPHER
    global random_generator
    USER_FILE.seek(0, 0)
    pos = 0
    while True:
        try:
            pos = USER_FILE.tell()
            info = USER_FILE.readline()
            info = eval(info)
        except:
            break
        if info['user'] == data['user']:
            response = {'type':11, 'user':data['user'], 'errorcode':1}
            response = json.dumps(response)
            send_message(response, {src_fd}, 0)
            return
    USER_FILE.seek(pos, 0)
    salt=create_salt()
    decrypted_pwd=CIPHER.decrypt(base64.b64decode(data['password'].encode("UTF-8")), random_generator)
    temp = {'user':data['user'], 'password':create_md5(decrypted_pwd, salt), 'time':0,"salt":salt,'nickname':data['nickname']}
    temp = str(temp)#不用json.dumps的原因是它不能处理byte类型的salt,而这个salt没有办法decode
    USER_FILE.write(temp + '\n')
    USER_FILE.flush()
    response = {'type':11, 'user':data['user'], 'errorcode':0}
    response = json.dumps(response)
    send_message(response, {src_fd}, 0)
    return

#创建新的小组
#如果小组已存在，返回报文errorcode:1，成功返回errorcode:0
def create_group(data, src_fd):
    global GROUP_INFO
    global USER_INFO
    group = data['group']
    user = data['user']
    if group in GROUP_INFO.keys():
        response = {'type':12, 'group':data['group'], 'errorcode':1}
        response = json.dumps(response)
        send_message(response, {src_fd}, 0)
        return
    GROUP_INFO[group] = {'password':data['password'], 'cnt':1, 'member':{user}}
    USER_INFO[user]['group'] = group
    response = {'type':12, 'group':data['group'], 'errorcode':0}
    response = json.dumps(response)
    send_message(response, {src_fd}, 0)
    return

#加入小组
#如果小组不存在，返回报文errorcode:1，如果密码错误返回errorcode:2
#成功返回errorcode:0
def enter_group(data, src_fd):
    global USER_INFO
    global GROUP_INFO
    group = data['group']
    user = data['user']
    if group not in GROUP_INFO.keys():
        response = {'type':13, 'group':data['group'], 'errorcode':1}
        response = json.dumps(response)
        send_message(response, {src_fd}, 0)
        return
    if GROUP_INFO[group]['password'] != data['password']:
        response = {'type':13, 'group':data['group'], 'errorcode':2}
        response = json.dumps(response)
        send_message(response, {src_fd}, 0)
        return
    GROUP_INFO[group]['member'].add(user)
    GROUP_INFO[group]['cnt'] = GROUP_INFO[group]['cnt'] + 1
    USER_INFO[user]['group'] = data['group']
    response = {'type':13, 'group':data['group'], 'errorcode':0}
    response = json.dumps(response)
    send_message(response, {src_fd}, 0)
    return

#退出小组，如果退出后，小组人数为0则删除该小组
#成功返回errorcode:0
def exit_group(data, src_fd):
    global GROUP_INFO
    global USER_INFO
    group = data['group']
    if '' == group:
        return
    user = data['user']
    USER_INFO[user]['group'] = ''
    GROUP_INFO[group]['member'].remove(user)
    GROUP_INFO[group]['cnt'] = GROUP_INFO[group]['cnt'] - 1
    if 0 == GROUP_INFO[group]['cnt']:
        del GROUP_INFO[group]
    response = {'type':14, 'group':data['group'], 'errorcode':0}
    response = json.dumps(response)
    send_message(response, {src_fd}, 0)
    return

#修改报文类型后，转发报文内容给小组中所有其它成员
def group_chat(data, src_fd):
    global USER_INFO
    global GROUP_INFO
    group = data['group']
    data['type'] = 15
    if '' == group:
        send_fd_set = {USER_INFO[member]['fd'] for member in USER_INFO.keys() if USER_INFO[member]['group'] == ''}
    else:
        send_fd_set = {USER_INFO[member]['fd'] for member in GROUP_INFO[group]['member']}
    message = json.dumps(data)
    send_message(message, send_fd_set, src_fd)
    return

#修改报文类型后，转发报文给对应账户的连接
def private_chat(data, src_fd):
    global USER_INFO
    target = data['target']
    if target not in USER_INFO.keys():
        send_fd_set = {src_fd}
    else:
        send_fd_set = {USER_INFO[target]['fd']}
    data['type'] = 16
    message = json.dumps(data)
    send_message(message, send_fd_set, 0)
    return

#如果请求方已经在小组内，则返回小组内的成员列表
#如果请求方不在小组里面，则返回所有聊天室的列表
def list_group(data, src_fd):
    global USER_INFO
    global GROUP_INFO
    group = data['group']
    if '' == group:
        member_list = [member for member in GROUP_INFO.keys()]
    else:
        member_list = [member for member in GROUP_INFO[group]['member']]
    message = {'type':19, 'group':group, 'list':member_list}
    message = json.dumps(message)
    send_message(message, {src_fd}, 0)
    return

#处理登陆报文，登陆成功后自动处于大厅
#如果账户已在线，则将之前登陆的连接踢下线
#如果账户不存在，则将返回报文errorcode:1
#如果密码错误，则返回报文errorcode:2
#成功返回errorcode:0
def login(data, src_fd):
    global USER_FILE
    global USER_INFO
    global ALL_SOCK
    global CIPHER
    global random_generator
    user = data['user']
    password = CIPHER.decrypt(base64.b64decode(data['password'].encode("UTF-8")), random_generator)
    USER_FILE.seek(0, 0)
    lines = USER_FILE.readlines()
    for info in lines:
        try:
            info = eval(info)
        except:
            break
        if info['user'] == user:
            if info['password'] != create_md5(password,info['salt']):
                response = {'type':17, 'user':data['user'], 'errorcode':2}
                message = json.dumps(response)
                send_message(message, {src_fd}, 0)
                return
            if user in USER_INFO.keys():                   #登陆将之前的人挤掉
                pre_fd = USER_INFO[user]['fd']
                ALL_SOCK.remove(pre_fd)
                pre_fd.close()
                USER_INFO[user]['fd'] = src_fd
            else:
                USER_INFO[user] = {'fd':src_fd, 'group':'', 'login_time':time.time()}
            response = {'type': 17, 'user': data['user'],'nickname':info['nickname'], 'errorcode': 0}  #登陆时发送nickname
            message = json.dumps(response)
            send_message(message, {src_fd}, 0)
            return
    response = {'type': 17, 'user': data['user'], 'errorcode': 1}
    message = json.dumps(response)
    send_message(message, {src_fd}, 0)
    return

#发送公钥
def send_pkey(src_fd):
    print("执行这里")
    global PUBLIC_PEM 
    response = {'type': 8, 'pubkey': PUBLIC_PEM.decode("UTF-8")}
    message = json.dumps(response)
    send_message(message, {src_fd}, 0)
    print("发好了")
    return

#接收到客户端请求报文，根据数据中的type选择不同的处理
def decode(data, src_fd):
    if dict != type(data):
        return
    msg_type = data['type']
    if 1 == msg_type:    #注册报文
        register(data, src_fd)
    elif 2 == msg_type:
        create_group(data, src_fd)
    elif 3 == msg_type:
        enter_group(data, src_fd)
    elif 4 == msg_type:
        exit_group(data, src_fd)
    elif 5 == msg_type:
        group_chat(data, src_fd)
    elif 6 == msg_type:
        private_chat(data, src_fd)
    elif 7 == msg_type:
        login(data, src_fd)
    elif 9 == msg_type:
        list_group(data, src_fd)
    elif 28==msg_type:
        get_pubkey(data)
    else:
        print ("信息错误!\n")
        
        

#接受首次连接
def firsthdl(connection):
	print("first")
	cli_fd, cli_addr = connection.accept()
	print ("建立连接: ", cli_addr)
	cli_fd.setblocking(False)
	cli_fd.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
	send_pkey(cli_fd)    #向新连接的客户端发送服务端公钥
	print("send_pkey OK")
	ALL_SOCK.append(cli_fd)                      #每次accept就将新的连接加入select监听的队列
	print("firsthdl OK")

#首次以后连接处理
def hdl(connection):
	print("hdl")
	data_buffer = bytes()
	while True:
		try:
			data = connection.recv(1024)
		except:
			clear_sock(connection)             #连接发生异常时清除错误连接
			break
		if data:
			#每次先解析出头部4个字节，查看包的大小，直到接收到足够多长度再进行数据解析
			data_buffer += data
			if len(data_buffer) < header_len:
				continue
			body_size = struct.unpack('i', data_buffer[:header_len])[0]
			if len(data_buffer) < header_len + body_size:
				continue
			data = data_buffer[header_len:header_len+body_size]
			message = data.decode()
			message = json.loads(message)
			decode(message, connection)
			if len(data_buffer) == header_len+body_size:
				break
			else:
				data_buffer = data_buffer[header_len+body_size:]
		else:
			clear_sock(connection)              #客户端主动断开，清除连接
			break

if __name__ == "__main__":
    init()
    sock_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = ('', 10000)
    sock_fd.bind(server_address)
    sock_fd.listen(100)
    print ("服务器开始监听: ", server_address)
	
    
    ALL_SOCK = [sock_fd]
    
    #将接收队列放进select中进行监听
    while True:
        readable, writeable, exceptional = select.select(ALL_SOCK, [], [])
        for connection in readable:
            if connection is sock_fd:
                t = threading.Thread(target=firsthdl, args=(connection,))
                t.start()
                t.join()
            else:
                t = threading.Thread(target=hdl, args=(connection,))
                t.start()
                t.join()
