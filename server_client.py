import socket


class Socket:
    def __init__(self, function, host='94.216.164.16'):
        self.function = function
        self.host = host
        self.port = 6978
        self.s = socket.socket()
        if self.function == 'REQUEST':
            Socket.client(self)
        if self.function == 'ANSWER':
            Socket.server(self)

    def client(self):
        self.s.bind((self.host, self.port))
        self.s.listen(5)

    def server(self):
        self.s.bind((self.host, self.port))
        self.s.listen(5)

    def send_request_for(self, files):
        self.s.send(bytes(self.function))
        for filename in files:
            self.s.send(filename)

    def answer_request(self):
        while True:
            (conn_sock, address) = self.s.accept()
            function = conn_sock.recv(4096)
            if function != b'REQUEST':
                break
            while True:
                filename = conn_sock.recv(500000)
                if not filename:
                    break
                with open(str(filename), 'wb') as f:
                    Socket.send_file(self, f)

    def send_file(self, file):
        data = file.read(500000)
        while data:
            self.s.send(data)
            data = file.read(500000)

    def rec_requested(self):
        files = []
        while True:
            (conn_sock, address) = self.s.accept()
            file = conn_sock.recv(500000)
            if not file:
                break
            files.append(file)
        return files
