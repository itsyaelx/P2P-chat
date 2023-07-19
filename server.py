from socket import *
from functionalities import *

HEADER = 16

#server info
host = '148.220.208.138'
port = 10000
address = (host, port)

#clients control
socketslist = []    # contiene los sockets activos para ser leídos
users       = {'user1': '1', 'user2': '2', 'user3':'3'}    # {'username' : 'password'}
clients     = {}    # {socket : (ip, int(port))} -------> [login] {socket: 'username'}
clients2    = {}    # {'username': socket}
activeUsers = {}    # {socket : ('ip', 'port')} 
keys        = {}    # {socket : b'public key'}

#crypto
public_key = ''
private_key = ''


private_key, public_key = generateKeys()
#print('Server key: ', public_key)

sock = socket(AF_INET, SOCK_STREAM)
sock.bind(address)
sock.listen(1)

sock.setblocking(0)

print('Esperando...')

while True:
    try:
        client, clientadd = sock.accept()
        print(f"{clientadd}::: Conexión exitosa")
        socketslist.append(client)
        clients[client] = clientadd
    except:
        pass

    if len(socketslist) > 0:
        for sockets in socketslist:
            message = recvmessages(sockets, HEADER)
            
            if message != 0:
                try:
                    message = message.decode('utf-8')
                except:
                    message = decryptMessage(private_key, message).decode('utf-8')
        
                if message == 'recvKey':
                    recvKey(sockets, keys, HEADER)
                    sendKey(sockets, HEADER, public_key)
                    sockets.setblocking(0)

                elif message == 'loginRequest':
                    loginRequest(sockets, private_key, users, keys, HEADER)
                    sockets.setblocking(0)

                elif message == 'login':
                    loginUser(sockets, private_key, activeUsers, clients, clients2, HEADER)
                    sockets.setblocking(0)

                elif message == 'createUser':
                    registerUser(sockets, private_key, keys, users, HEADER)
                    sockets.setblocking(0)

                elif message == 'requestUser':
                    recvRequest(sockets, private_key, clients, clients2, keys, HEADER)
                    sockets.setblocking(0)

                elif message == 'responseRequest':
                    responseChatRequest(sockets, keys, private_key, clients, clients2, activeUsers, HEADER)
                    sockets.setblocking(0)
                elif message == 'logout':
                    logoutclient(sockets, clients, clients2, activeUsers)
                else:
                    print(f"{clients[sockets]} > {message}")

