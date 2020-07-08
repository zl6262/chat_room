# -*- coding:utf-8 -*-

#2018.5.31  hash 版本
import socket
import sys
import threading
import getpass
import struct
import select
import json
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
from random import Random
from hashlib import md5
import base64
header_len = 4
SERVER_IP="58.243.223.40"#'140.143.66.173' 58.243.223.40 127.0.0.1
USER = ''
Group = ''
sock_fd = 0
header_len = 4
pubkey=''
cipher=''
#获取publicKey 
def get_pubkey(data):
    #print("执行了")
    global cipher
    rsakey=RSA.importKey(data['pubkey'])
    cipher=Cipher_pkcs1_v1_5.new(rsakey)
#粘包阻塞 接收函数
def packet_accept():
    #print("开始收")
    data_buffer = bytes()
    while True:
        data = sock_fd.recv(1024)
        #print ("收到一个")             
        if data:
            data_buffer += data
            if len(data_buffer) < header_len:
                continue
            body_size = struct.unpack('i', data_buffer[:header_len])[0]
            if len(data_buffer) < header_len + body_size:
                continue
            data = data_buffer[header_len:header_len + body_size]
            data = data.decode()
            data = json.loads(data)
            decode(data)
            break
#加密函数
#def encrypt(password,key):
#    cipher=Cipher_pkcs1_v1_5.new(key)
#    rsapwd=base64.b64encode(cipher.encrypt(password))
#    return rsapwd
#注册函数   
def do_register():
    global sock_fd
    global cipher
    while True:
        print ("请输入你的用户名（由不少于6个英文字符或数字组成）： ")
        user = sys.stdin.readline().strip('\n')
        if len(user) < 6:
            print ("用户名长度不能小于6！")
            continue
        if not user.isalnum():
            print ("用户名只能由英文字母或数字组成！")
            continue
        if not user[0].isalpha():
            print ("用户名的第一个字符必须是英文字母！")
            continue
        break
    while True:
        password =getpass.getpass("请输入你的密码（长度3~16）： ")
        if len(password) > 16 or len(password) < 3:
            print ("密码长度必须大于3小于16！")
            continue
        if ' ' in password:
            print ("密码不能包含空格!")
            continue
        break
    password=base64.b64encode(cipher.encrypt(password.encode("UTF-8"))).decode("UTF-8")
    #密钥以及加密后的均是bytes类型 不支持json  只能将其decode成utf-8string类型发送， 而进行加密时 password是
    #string 变量 不能加密 要用encode 转换成bytes类型才能继续  encode 返回bytes
    print("请输入用户昵称")
    nickname = sys.stdin.readline().strip('\n')
    data = {'type':1, 'user':user, 'password':password, 'nickname':nickname}
    body = json.dumps(data)
    length = len(body)
    send_data = struct.pack('i', length) + body.encode()
    sock_fd.sendall(send_data)
    data_buffer = bytes()
    while True:
        data = sock_fd.recv(1024)             
        if data:
            data_buffer += data
            if len(data_buffer) < header_len:
                continue
            body_size = struct.unpack('i', data_buffer[:header_len])[0]
            if len(data_buffer) < header_len + body_size:
                continue
            data = data_buffer[header_len:header_len + body_size]
            data = data.decode()
            data = json.loads(data)
            break
    if 1 == data['errorcode']:
        print ("注册失败： 用户名:%s 已被注册！" % data['user'])
    elif 0 == data['errorcode']:
        print ("注册成功： 您好:%s" % data['user'])
    return

#登陆函数
def do_login():
    global USER
    global sock_fd
    while True:
        print ("请输入用户名: ")
        user = sys.stdin.readline().strip('\n')
        if len(user) < 6:
            print ("用户名长度不能小于6！")
            continue
        if not user.isalnum():
            print ("用户名只能由英文字母或数字组成！")
            continue
        if not user[0].isalpha():
            print ("用户名的第一个字符必须是英文字母！")
            continue
        break
    while True:
        password = getpass.getpass("请输入你的密码： ")
        if len(password) > 16 or len(password) < 3:
            print ("密码长度必须大于3小于16！")
            continue
        if ' ' in password:
            print ("密码不能包含空格!")
            continue
        break
    password=base64.b64encode(cipher.encrypt(password.encode("UTF-8"))).decode("UTF-8")
    data = {'type': 7, 'user': user, 'password': password}
    body = json.dumps(data)
    length = len(body)
    send_data = struct.pack('i', length) + body.encode()
    sock_fd.sendall(send_data)

    data_buffer = bytes()
    while True:
        data = sock_fd.recv(1024)                       
        if data:
            data_buffer += data
            if len(data_buffer) < header_len:
                continue
            body_size = struct.unpack('i', data_buffer[:header_len])[0]
            if len(data_buffer) < header_len + body_size:
                continue
            data = data_buffer[header_len:header_len + body_size]
            data = data.decode()
            data = json.loads(data)
            break
    if 1 == data['errorcode']:
        print ("用户名：%s 不存在！" % data['user'])
        return False
    elif 2 == data['errorcode']:
        print ("密码错误")
        return False
    elif 0 == data['errorcode']:
        print ("登陆成功 您好：%s" % data['user'])
        print ("*******************************************************")
        USER = data['user']
        return True
    return False
def nickname():
    print("请输入你想设置的昵称:")
    nickname = sys.stdin.readline().strip('\n')
    data={'type':9,'nickname':nickname}
    body = json.dumps(data)
    length = len(body)
    send_data = struct.pack('i', length) + body.encode()
    sock_fd.sendall(send_data)
    packet_accept()
#创建小组
def create_group(groupname):
    global sock_fd
    if '' != Group:
        print ("你已经在小组中了！")
        return
    if len(groupname) < 6:
        print ("小组名长度不能小于6！")
        return
    if not groupname.isalnum():
        print ("小组名只能由英文字母或数字组成！")
        return
    while True:
        password =getpass.getpass("请设置小组密码： ")
        if len(password) > 16 or len(password) < 3:
            print ("密码长度必须大于3小于16！")
            continue
        if ' ' in password:
            print ("密码不能包含空格!")
            continue
        break
    data = {'type':2, 'user':USER, 'group':groupname, 'password':password}
    body = json.dumps(data)
    length = len(body)
    send_data = struct.pack('i', length) + body.encode()
    try:
        sock_fd.sendall(send_data)
    except:
        print ("发送请求失败")
    return

#进入小组
def enter_group(groupname):
    global sock_fd
    if '' != Group:
        print ("你已经在小组里了")
        return
    if len(groupname) < 6:
        print ("小组名长度不能小于6！")
        return
    if not groupname.isalnum():
        print ("小组名只能由英文字母或数字组成！")
        return
    while True:
        password = getpass.getpass("请输入小组密码：")
        if len(password) > 16 or len(password) < 3:
            print ("密码长度必须大于3小于16！")
            continue
        if ' ' in password:
            print ("密码不能包含空格!")
            continue
        break
    data = {'type': 3, 'user': USER, 'group':groupname, 'password': password}
    body = json.dumps(data)
    length = len(body)
    send_data = struct.pack('i', length) + body.encode()
    try:
        sock_fd.sendall(send_data)
    except:
        print ("发送请求失败！")
    return

#退出小组
def exit_group():
    global sock_fd
    if '' == Group:
        print ("你还没有加入小组")
        return
    data = {'type': 4, 'user': USER, 'group':Group}
    body = json.dumps(data)
    length = len(body)
    send_data = struct.pack('i', length) + body.encode()
    try:
        sock_fd.sendall(send_data)
    except:
        print ("发送请求失败！")
    return

#列出所有小组
def list_group():
    global sock_fd
    global Group
    data = {'type':9, 'group': Group}
    body = json.dumps(data)
    length = len(body)
    send_data = struct.pack('i', length) + body.encode()
    try:
        sock_fd.sendall(send_data)
    except:
        print ("发送请求失败！")
    return

#聊天室的消息报文
def group_chat(content):
    global sock_fd
    if '' == content:
        return
    data = {'type': 5, 'user': USER, 'group':Group, 'content': content}
    body = json.dumps(data)
    length = len(body)
    send_data = struct.pack('i', length) + body.encode()
    try:
        sock_fd.sendall(send_data)
    except:
        print ("发送消息失败！")
    return

#私聊的报文
def private_chat():
    global sock_fd
    while True:
        print ("要私聊的用户的用户名：")
        target = sys.stdin.readline().strip('\n')
        if len(target) < 6:
            print ("用户名长度不能小于6！")
            continue
        if not target.isalnum():
            print ("用户名只能由英文字母或数字组成！")
            continue
        if not target[0].isalpha():
            print ("用户名的第一个字符必须是英文字母！")
            continue
        break
    print ("请输入聊天内容：")
    content = sys.stdin.readline().strip('\n')
    #content = content.decode('utf8')
    data = {'type': 6, 'user': USER, 'target': target, 'content': content}
    body = json.dumps(data)
    length = len(body)
    send_data = struct.pack('i', length) + body.encode()
    try:
        sock_fd.sendall(send_data)
    except:
        print ("发送消息失败！")
    return

#创建小组的回应报文处理
def creat_group_rep(data):
    global Group
    if 1 == data['errorcode']:
        print ("小组已存在!")
    elif 0 == data['errorcode']:
        Group = data['group']
        print ("创建小组成功，小组名为：%s" % data['group'])
        print ("******************************************************")
    return

#加入小组的报文处理
def enter_group_rep(data):
    global Group
    if 1 == data['errorcode']:
        print ("小组不存在")
        print ("******************************************************")
    elif 2 == data['errorcode']:
        print ("密码错误！")
    elif 0 == data['errorcode']:
        print ("加入成功")
        Group = data['group']
    return

#退出小组的报文处理
def exit_group_rep(data):
    global Group
    if 0 == data['errorcode']:
        print ("已退出小组: %s" % data['group'])
        print ("******************************************************")
        Group = ''
    return


#处理列表请求回应报文
#根据报文中的小组信息选择打印内容是小组列表还是成员列表
def list_group_rep(data):
    global Group
    if Group != data['group']:
        return
    member_list = data['list']
    i = 1
    if '' == data['group']:
        print ("小组列表:")
        for member in member_list:
            print ("%d. %s" % (i, member))
            i = i + 1
    else:
        print ("小组成员名单:")
        for member in member_list:
            print ("%d. %s" % (i, member))
            i = i + 1
    print ("*******************************************************")
    return

#接收并打印小组内其它成员发来的聊天报文
def group_chat_rep(data):
    if USER != data['user']:
        if '' != Group:
            print ("<%s>%s: %s" % (data['group'], data['user'], data['content']))
        else:
            print ("<大厅>%s: %s" % (data['user'], data['content']))


#接收并打印私聊报文
def private_chat_rep(data):
    if USER == data['user']:
        print ("目标用户不能是自己！")
        return
    print ("****************")
    print ("******%s to you: %s" % (data['user'], data['content']))
    print ("****************")
    return

#根据从服务器发来报文的type决定处理函数
def decode(data):
    if dict != type(data):
        return
    msg_type = data['type']
    if 12 == msg_type:
        creat_group_rep(data)
    elif 13 == msg_type:
        enter_group_rep(data)
    elif 14 == msg_type:
        exit_group_rep(data)
    elif 15 == msg_type:
        group_chat_rep(data)
    elif 16 == msg_type:
        private_chat_rep(data)
    elif 19 == msg_type:
        list_group_rep(data)
    elif 8  == msg_type:
        get_pubkey(data)
    else:
        print ("信息错误!\n")


#根据输入的字符，确定处理函数
def wait_input():
    while True:
        msg = sys.stdin.readline().strip('\n')
        cmd=msg.split()[0]
        if '#create' == cmd:                      #创建小组
            if len(msg.split())==2:
                create_group(msg.split()[1])
            else:
                print("命令用法：#create <小组名> 小组名长度不能小于6")
        elif '#enter' == cmd:                     #加入小组
            if len(msg.split())==2:
                enter_group(msg.split()[1])
            else:
                print("命令用法：#enter <小组名> 小组名长度不能小于6")
        elif '#exit' == cmd:                      #退出小组
            exit_group()
        elif '#private' == cmd:                   #私聊
            private_chat()
        elif '#list' == cmd:                      #获取小组列表或者小组内成员列表
            list_group()
        else:
            input = msg#.decode('utf8')     			#默认在大厅或者小组内说话
            if '' != Group:
                print ("<%s>You: %s" % (Group, input))
            else:
                print ("<大厅>You: %s" % input)
            group_chat(input)
#socket连接服务器
if __name__ == "__main__":
    sock_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = (SERVER_IP, 10000)
    while True:
        try:
            ret = sock_fd.connect(server_address)
            #print ("连接成功-stg1")
            packet_accept()
            print ("连接成功")
            break
        except:
            print ('连接失败，重新尝试连接')

#与服务器进行信息的匹配
    while True:
        print ("请按下对应数字以完成相应功能")
        print ("  1.注册  2.登陆")
        input = sys.stdin.readline().strip('\n')
        try:
            input = int(input)
        except:
            print ("******请输入 '1' 或 '2'!")
            continue
        if 1 == input:
            do_register()
            continue
        elif 2 == input:
            ret = do_login()
            if ret:
                break

#创建新的线程监视控制台输入信息
    t = threading.Thread(target=wait_input)
    t.setDaemon(True)
    t.start()

    inputs = [sock_fd]
    while True:
        readable, writeable, exceptional = select.select(inputs, [], [])
        for event in inputs:
            data_buffer = bytes()
            while True:
                data = event.recv(1024)
                if data:
                    data_buffer += data
                    if len(data_buffer) < header_len:
                        continue
                    body_size = struct.unpack('i', data_buffer[:header_len])[0]
                    if len(data_buffer) < header_len + body_size:
                        continue
                    data = data_buffer[header_len:header_len + body_size]
                    data = data.decode()
                    data = json.loads(data)
                    ret = decode(data)
                    if len(data_buffer) == header_len + body_size:
                        break
                    else:
                        data_buffer = data_buffer[header_len + body_size:]
                else:
                    print ("未连接")
                    inputs.remove(event)
                    break
