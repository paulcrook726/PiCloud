import socket


class ClientSocket:
    def __init__(self):
        self.host = socket.gethostname()
        self.port = 6969
        self.socket = socket.socket()
        self.socket.connect((self.host, self.port))
        with open("/home/paul/Music/Firecracker.mp3", 'rb') as file:
            byte = file.read(1024)
            while byte:
                print("Sending")
                self.socket.send(byte)
                byte = file.read(1024)
        print("Done!")
        self.socket.close()

client = ClientSocket()
