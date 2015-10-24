import socket
import sys


class ServerSocket:
    def __init__(self):
        self.socket = socket.socket()
        self.host = socket.gethostname()
        self.port = 6969
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        while True:
            (conn_socket, address) = self.socket.accept()
            byte = conn_socket.recv(1024)
            with open("file.mp3", 'wb') as file:
                with open("logfile.txt", 'wb') as logfile:
                    while byte:
                        log = "Receiving connection from: " + address
                        file.write(bytes)
                        byte = conn_socket.recv(1024)
                        logfile.writelines(log)
            print("Finished receiving data.")
            conn_socket.close()
            sys.exit(0)

server = ServerSocket()
