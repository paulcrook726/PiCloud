import socket


host = socket.gethostname()
port = 6962
s = socket.socket()


s.connect((host, port))
with open("/home/paul/text.txt", 'rb') as f:
    byte = f.read(500000)
    while byte:
        s.send(byte)
        print("Sending...")
        byte = f.read(500000)
print("Done!")
s.close()
