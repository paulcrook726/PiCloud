"""
This module is the primary building block of the PyCloud infrastructure.  Within it, the basic file transfer protocol is
laid down.
"""
import socket
import struct
import threading
import os
import logging
import hashlib
import uuid
import nacl.public
import nacl.encoding
import nacl.utils


class ClientSocket(socket.socket):
    """
    This is a subclass of ``socket.socket``.  Introduced primarily for simplicity and the setting of pre-defined
    values.
    """
    def __init__(self, host, port):
        """
        Defines connecting address and connects to it.


        :param host: Host IP or hostname of desired peer socket.
        :type host: str
        :param port: Port number of server service.
        :type port: int
        """
        socket.socket.__init__(self)
        self.host = host
        self.port = port
        self.connect((self.host, self.port))


class ServerSocket(socket.socket):
    """This is a subclass of ``socket.socket``.  Creates a socket with a few pre-defined variables."""
    def __init__(self, port):
        """
        Sets address as reusable.  Binds and listens on the address.


        :param port: Port number to listen on.
        :type port: int
        """
        socket.socket.__init__(self)
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.port = port
        self.bind((socket.gethostname(), self.port))
        self.listen(5)

    def activate(self):
        """
        This activates the main server event loop for accepting incoming connections.
        """
        while True:
            (new_socket, (ip, port)) = self.accept()
            logging.info('[+]  Incoming connection from: %s:%i', ip, port)
            new_thread = threading.Thread(target=ConnectionSession, args=(new_socket, (ip, port), ))
            new_thread.start()


class ConnectionSession:
    def __init__(self, sock, address, is_server=True):
        self.sock = sock
        self.ip = address[0]
        self.port = address[1]
        self.filename = ''
        self.ext = ''
        self.username = ''
        self.pwd = b''
        self.is_server = is_server
        if self.is_server is True:
            self.server()
        elif self.is_server is False:
            self.client()

    def server(self):
        hex_keygen()
        process_key_file(recv_all(self.sock))
        send_file(self.sock, pre_proc('.public.key', is_server=1))
        while self.start() == 0:
            pass

    def client(self):
        hex_keygen()
        send_file(self.sock, pre_proc('.public.key'))
        process_key_file(recv_all(self.sock))

    def process_file(self, file):
        file_list = file.split(b'::::::::::')  # split data along delimiter
        logging.info('[+]  Received data from: %s:%i', self.ip, self.port)
        try:  # check if delimiter exists in data.  If this happens, the data will be compromised.
            x = file_list[-4]
            logging.info("[-]  Delimiter has been found in multiple areas, causing %i bytes to be left out.  "
                         "This causes incomplete file writes.  Exiting now!", len(x))
            self.sock.close()
            return 1
        except IndexError:
            pass
        try:
            self.ext = str(file_list[2], encoding='utf-8')
        except IndexError:
            self.ext = ''
        self.filename = str(file_list[1], encoding='utf-8')
        logging.info('[+]  The file %s.%s was received.', self.filename, self.ext)
        if len(file_list) > 1:
            send_encrypted_file(self.sock, b'FileReceived')
            file_data = file_list[0]
            return self.evaluate_contents(file_data)
        else:
            logging.info('[-]  File Request')
            send_encrypted_file(self.sock, pre_proc((self.filename + self.ext), is_server=1))
            return 0

    def evaluate_contents(self, file_data):
        if self.ext == 'id':
            self.username = self.filename
            self.pwd = file_data
            if os.path.exists(self.username) is True:  # login request from client
                log_in = self.login()
                if log_in == 1:
                    logging.info('[-]  Failed login attempt by %s', self.username)
                    send_encrypted_file(self.sock, b'[-]  Login attempt failed')
                    return log_in
                elif log_in == 0:
                    logging.info('[+]  Successful login attempt by %s', self.username)
                    send_encrypted_file(self.sock, b'[+]  Login attempt successful')
                    return log_in
            else:  # registration request from client
                os.makedirs(self.username)
                reg = self.register()
                if reg == 1:
                    logging.info('[-]  Failed registration attempt from %s', self.username)
                    send_encrypted_file(self.sock, b'[-]  Registration attempt failed')
                    return reg
                elif reg == 0:
                    logging.info('[-]  Successful user account registration for %s', self.username)
                    send_encrypted_file(self.sock, b'[+]  Registration attempt successful')
                    return reg
        else:
            current_user = self.username
            try:
                with open(current_user + self.filename + '.' + self.ext, 'wb') as f:
                    f.write(file_data)
            except IsADirectoryError:
                pass
            return 0

    def start(self):
        encrypted_msg = recv_all(self.sock)
        if encrypted_msg is None:
            return 1
        private_key = get_private_key()
        public_key = get_other_public_key()
        box = nacl.public.Box(private_key, public_key)
        msg = box.decrypt(encrypted_msg)
        if b'::::::::::' in msg:  # indicated that the msg is a filename (possibly only a request for a filename)
            file = msg
            return self.process_file(file)
        else:  # msg is a small message used in the transfer protocol
            if msg == b'FileError':
                logging.info('[-]  Request could not be found')
                self.sock.close()
                return 1
            elif msg == b'FileReceived':
                logging.info('[+]  Sent file was successfully received')
                return 0
            elif msg is None:
                self.sock.close()
                return 1
            elif msg.split(b':')[0] == b'InputRequest':

                answer = input(str(msg.split(b':')[1], encoding='utf-8'))
                send_encrypted_file(self.sock, bytes(answer, encoding='utf-8'))
                return 0
            elif msg == b'Logout':
                logging.info('[-]  Client session logging out')
                send_encrypted_file(self.sock, b'Logout')
                self.sock.close()
                return 1
            elif msg.split(b':')[0] == b'MKDIR':
                user_folder = self.username
                os.makedirs(user_folder + msg.split(b':')[1].decode(encoding='utf-8'), exist_ok=True)
                logging.info('[+]  Successfully synced directory.')
                send_encrypted_file(self.sock, b'FileReceived')
                return 0

    def login(self):
        raw_pwd, salt = get_usr_pwd(self.username)
        msg = 'Incorrect username or password.\n' \
              '[1] Exit\n' \
              '[2] Register an account under this name and password\n'
        if raw_pwd == 1:
            answ = self.input_request(msg)
            if answ == '1':
                return 1
            elif answ == '2':
                return self.register()
        if verify_hash(self.pwd, raw_pwd, salt=salt) is True:
            return 0
        else:
            answ = self.input_request(msg)
            if answ == '1':
                return 1
            elif answ == '2':
                return self.register()

    def input_request(self, msg):
        msg = 'InputRequest:' + msg
        send_encrypted_file(self.sock, bytes(msg, encoding='utf-8'))
        answer = str(recv_all(self.sock), encoding='utf-8')
        return answer

    def register(self):
        hashed_pwd, salt = hash_gen(self.pwd)
        if get_usr_pwd(self.username) == 1:
            with open('.pi_users', 'ab') as f:
                line = bytes(self.username, encoding='utf-8') + b':' + salt + b':' + hashed_pwd + b'\n'
                f.write(line)
            return self.login()
        else:
            return 1


def hash_gen(pwd, salt=None):
    try:
        pwd = bytes(pwd, encoding='utf-8')
    except TypeError:
        pass
    if salt is None:
        salt = uuid.uuid4().bytes
    try:
        hashed_pwd = hashlib.pbkdf2_hmac('sha512', pwd, salt, 100000)
    except TypeError:
        salt = bytes(salt, encoding='utf-8')
        hashed_pwd = hashlib.pbkdf2_hmac('sha512', pwd, salt, 100000)
    return hashed_pwd, salt


def verify_hash(pwd, hashed_pwd, salt):
    possible_pwd, salt = hash_gen(pwd, salt=salt)
    return possible_pwd == hashed_pwd


def recv_all(client_sock):
    """
    This function receives data on a socket by processing the data length at first.


    :param client_sock: The socket by which data is being received.
    :type client_sock: socket.socket


    :return: Returns ``None`` if no data is received.
    :rtype: None
    :return: Otherwise returns the data received.
    :rtype: byte str
    """
    raw_len = proc_block(client_sock, 4)
    if raw_len is None:
        return None
    packet_len = struct.unpack('>I', raw_len)[0]
    if packet_len > (2048**2):  # If the file is greater than 2mb, it is divided up into 2mb blocks,
        block = b''             # then block by block received and added to the block variable, then returned
        while len(block) < packet_len:
            block = proc_block(client_sock, (2048**2)) + block
            print('[+]  Receiving...')
        return block
    else:
        return proc_block(client_sock, packet_len)


def proc_block(client_sock, length):
    """
    This is a helper function of ``recv_all()``.  It receives data according to ``length``.


    :param client_sock: The socket by which data is received.
    :type client_sock: socket.socket
    :param length: The length of the data to check for and receive.
    :type length: int


    :return: Returns ``None`` if no packets are received.  Otherwise returns the block of data received.
    :rtype: None or byte str
    """
    block = b''
    while len(block) < length:
        packet = client_sock.recv(length)
        if not packet:
            return None
        block += packet
    return block


def send_file(sock, b_data):
    """
    This function sends a byte string over a connected socket.


    :param sock: The socket by which data is sent.
    :type sock: socket.socket
    :param b_data: The data to be sent.
    :type b_data: byte str


    :return: Returns ``0`` upon success.
    :rtype: int
    :return: Returns ``None`` on failure.
    :rtype: None
    """
    length = len(b_data)
    b_data = struct.pack('>I', length) + b_data
    sent = 0
    buffer_size = 1024**2
    while sent < length:
        to_send = b_data[:buffer_size-1]
        just_sent = sock.send(to_send)
        sent += just_sent
        b_data = b_data[buffer_size-1:]
    logging.info('[+]  Successfully sent data')
    return 0


def send_encrypted_file(sock, b_data):
    private_key = get_private_key()
    public_key = get_other_public_key()
    box = nacl.public.Box(private_key, public_key)
    nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
    encrypted = box.encrypt(b_data, nonce)
    return send_file(sock, encrypted)


def pre_proc(filename, is_server=0):
    """
    This function processes a filename by whether or not it exists in the current working directory.


    :param filename: The filename of the file you want to process.
    :type filename: str
    :param is_server: This acts as a flag for determining how exactly the function should work.
    :type is_server: int


    :return: Returns the file data if it is found in the local filesystem.
    :rtype: byte str
    :return: Returns the pre-processed filename and extension if the function
    acts as a client. (For requesting files)
    :rtype: byte str
    :return: Returns ``FileError`` if function is acting as a server, and the file could not be
             found in the local filesystem.
    :rtype: byte str
    """
    try:
        file_ext = bytes(filename.split('.')[1], encoding='utf-8')
    except IndexError:
        file_ext = ''
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
        return data
    elif is_server == 0:
        data = name + delimiter + file_ext
        return data
    elif is_server == 1:
        logging.info('[-]  %s.%s does not exist.  Notifying client.', str(name, encoding='utf-8'),
                     str(file_ext, encoding='utf-8'))
        return b'FileError'
        # The file doesn't exist on the local filesystem.
        # The function will now return encoded data usable for requesting the file from a server


def hex_keygen():
    private_key = nacl.public.PrivateKey.generate()
    public_key = private_key.public_key
    private_key = private_key.encode(encoder=nacl.encoding.HexEncoder)
    public_key = public_key.encode(encoder=nacl.encoding.HexEncoder)
    with open('.public.key', 'wb') as f:
        f.write(public_key)
    with open('.private.key', 'wb') as t:
        t.write(private_key)


def get_usr_pwd(username):
    with open('.pi_users', 'ab+') as f:
        f.seek(0)
        for line in f:
            line_list = line.split(b':')
            if bytes(username, encoding='utf-8') == line_list[0]:
                raw_pwd = line_list[2].strip(b'\n')
                salt = line_list[1]
                return raw_pwd, salt
            else:
                pass
    return 1


def get_other_public_key():
    with open('.otherpublic.key', 'r+b') as f:
        public_key = f.readline()
    public_key = public_key.split(b'::::::::::')[0]
    return nacl.public.PublicKey(public_key, encoder=nacl.encoding.HexEncoder)


def get_private_key():
    with open('.private.key', 'r+b') as f:
        private_key = f.readline()
    return nacl.public.PrivateKey(private_key, encoder=nacl.encoding.HexEncoder)


def process_key_file(key_file):
    with open('.otherpublic.key', 'w+b') as file:
        file.write(key_file)
