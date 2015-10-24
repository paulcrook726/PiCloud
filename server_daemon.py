import socket

class Socket:
    def __init__(self):
        self.socket = socket.socket()
        self.host = socket.gethostname()
        self.port = 6969
        self.socket.bind(self.host, self.port)
        self.socket.listen(5)

    def run(self):
        while True:
            (conn_socket, address) = self.socket.accept()
            print("Receiving connection from: " + address)
            conn_socket.send(b"Connected to Picloud!")
            conn_socket.close()
