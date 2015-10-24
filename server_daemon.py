import socket


s = socket.socket()
host = socket.gethostname()
port = 6962


s.bind((host, port))
s.listen(5)

while True:
    (conn_socket, address) = s.accept()
    print("Received connection from" + str(address))
    byte = conn_socket.recv(500000)
    if not byte:
        print("Done")
        break
    print("Receiving")
    with open("file.txt", 'wb') as f:
        f.write(byte)
    conn_socket.close()
