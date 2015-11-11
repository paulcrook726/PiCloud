import socket
import struct
import threading
import os
import logging


def recv_all(client_sock):
    raw_len = proc_block(client_sock, 4)
    if raw_len is None:
        return None
    packet_len = struct.unpack('>I', raw_len)[0]
    if packet_len > (2048**2):  # If the file is greater than 1mb, it is divided up into 1mb blocks,
        block = b''             # then block by block received and added to the block variable, then returned
        while len(block) < packet_len:
            block = proc_block(client_sock, (2048**2)) + block
            print((len(block)/packet_len)*100, '% completed')
        return block
    else:
        return proc_block(client_sock, packet_len)


def proc_block(client_sock, length):
    block = b''
    while len(block) < length:
        packet = client_sock.recv(length)
        if not packet:
            return None
        block += packet
    return block


def send_file(sock, b_data):
    """This function structures a single file (in byte string) into the form: [length of byte string + byte string].
    Then it sends the structured data to the connected socket."""
    b_data = struct.pack('>I', len(b_data)) + b_data
    sock.sendall(b_data)


def evaluate(ip, port, sock):
    data = recv_all(sock)
    logging.info('[+]  Received data from: %s:%i', ip, port)
    data = data.split(b'::::::::::')
    try:
        test = data[-4]
        logging.info("Delimiter has been found in multiple areas.  This causes incomplete file writes.  "
                     "Exiting now!")
        sock.close()
    except:
        pass
    file_ext = str(data[-1], encoding='utf-8')
    name = str(data[-2], encoding='utf-8')
    logging.info('%s.%s received.', name, file_ext)
    if len(data) > 2:
        file = data[-3]
        with open(name+'.'+file_ext, 'wb') as filename:
            filename.write(file)
    else:
        logging.info('File Request')
        send_file(sock, pre_proc((name+'.'+file_ext), is_server=1))


def pre_proc(filename, is_server=0):
    """The pre_proc function opens a file name with the name "filename" (directory and file extension included!), and
    then encodes the data into byte string, while encoding key info into the communication protocol.  If the filename
    does not exist on the local drive, and the function is being used as a client (is_server = 0),
    it will return an encoded request for that file."""

    file_ext = bytes(filename.split('.')[1], encoding='utf-8')
    name = bytes(filename.split('.')[0], encoding='utf-8')
    delimiter = b'::::::::::'
    if os.path.isfile(filename) is True:
        # This commences local file reading and encoding into
        # byte string for file transfer, since the file exists.  This is basically getting the file
        # ready for uploading
        data = b''
        with open(filename, 'rb') as file:
            # Writing file binary data to variable 'data'.
            for line in file:
                data += line
        data += delimiter + name + delimiter + file_ext
        #  This structures the byte string into data<>name<>file extension.  This will later be
        #  decoded in order to store the data under the name and file extension.
        return data
    elif is_server == 0:
        data = name + delimiter + file_ext
        return data
    elif is_server == 1:
        logging.info('%s.%s does not exist.  Notifying client.', name, file_ext)
        return b'FileError'
        # The file doesn't exist on the local filesystem.
        # The function will now return encoded data usable for requesting the file from a server


class ClientSocket(socket.socket):
    def __init__(self, host, port):
        socket.socket.__init__(self)
        self.host = host
        self.port = port
        self.connect((self.host, self.port))


class ServerSocket(socket.socket):
    def __init__(self, port):
        socket.socket.__init__(self)
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.port = port
        self.bind((socket.gethostname(), self.port))
        self.listen(5)

    def activate(self):
        while True:
            (new_socket, (ip, port)) = self.accept()
            logging.info('Incoming connection from: %s:%i', ip, port)
            new_thread = threading.Thread(target=evaluate, args=(ip, port, new_socket))
            new_thread.start()


def main():
    logging.basicConfig(format='%(asctime)s %(message)s', filename='picloud.log', level=logging.INFO)
    c = ClientSocket('192.168.2.194', 46000)
    f = pre_proc('random.txt')
    send_file(c, f)
    print(str(recv_all(c), encoding='utf-8'))


if __name__ == '__main__':
    main()
