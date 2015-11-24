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


class ConnectionSession:
    def __init__(self, sock, address, is_server=True):
        self.sock = sock
        self.ip = address[0]
        self.port = address[1]
        self.filename = ''
        self.ext = ''

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
        self.ext = str(file_list[-1], encoding='utf-8')
        self.filename = str(file_list[-2], encoding='utf-8')
        logging.info('[+]  The file %s.%s was received.', self.filename, self.ext)
        if len(file_list) > 2:
            send_file(self.sock, b'FileReceived')
            data = file_list[-3]
            file = ReceivedFile(name, file_ext, sock)
            file.take_data(data)
            file.evaluate()
            return 0
        else:
            logging.info('[-]  File Request')
            send_file(self.sock, pre_proc((self.filename+'.'+ self.ext), is_server=1))
            return 0
        
    def process(self):
        data = recv_all(self.sock)
        if b'::::::::::' in data:  # indicated that the data is a filename (possibly only a request for a filename)
            file = data
            self.process_file(file)
        else:  # data is a small message used in the transfer protocol
            if data == b'FileError':
                logging.info('[-]  Request could not be found')
                sock.close()
                return 1
            elif data == b'FileReceived':
                logging.info('[+]  Sent file was successfully received')
                return 1
            elif data is None:
                sock.close()
                return 1
            elif data.split(b':')[0] == b'InputRequest':

                answer = input(str(data.split(b':')[1], encoding='utf-8'))
                send_file(sock, bytes(answer, encoding='utf-8'))
                return 0
            else:
                logging.info(str(data, encoding='utf-8'))

class User:
    def __init__(self, name, pwd, sock):
        """
        The ``User`` class is instanced every time the server receives a .id file.  The instance creates an environment
        for user interface with the server.


        :param name: Username used for naming/registration/login
        :type name: str
        :param pwd: User password for logging in/registering
        :type pwd: str
        :param sock: socket object used for communicating with the client
        :type sock: socket.socket
        """
        self.name = name
        self.pwd = pwd
        self.sock = sock

    def check_pwd(self):
        """
        This method checks the .pi_users file for ``self.name``.


        :return: Returns the corresponding password to the instance username.  If it is not found, ``1`` is returned.
        :rtype: str or int
        """
        with open('.pi_users', 'ab+') as f:
            f.seek(0)
            for line in f:
                line_list = line.split(b':')
                if bytes(self.name, encoding='utf-8') == line_list[0]:
                    raw_pwd = line_list[2].strip(b'\n')
                    salt = line_list[1]
                    return raw_pwd, salt
                else:
                    pass
            return 1

    def login(self):
        """
        This method logs in the User instance with the instance password and username.


        :return: Returns 0 on success.  Returns 1 on failure to login.
        :rtype: int
        """
        raw_pwd, salt = self.check_pwd()
        msg = 'Incorrect username or password.\n' \
              '[1] Exit\n' \
              '[2] Register an account under this name and password\n'
        if raw_pwd == 1:
            answ = self.input_request(msg)
            if answ == '1':
                return 1
            elif answ == '2':
                self.register()
            return 1

        if verify_hash(self.pwd, raw_pwd, salt=salt) is True:
            with open('.current_user', 'w') as f:
                f.write(self.name)
            return 0
        else:
            answ = self.input_request(msg)
            if answ == '1':
                return 1
            elif answ == '2':
                return self.register()
            return 1

    def register(self):
        """
        This method registers the User instance with the username and password, and then logs in via ``self.login()``.


        :return: Returns 1 on failure.  Returns 0 on success.
        :rtype: int
        """
        hashed_pwd, salt = hash_gen(self.pwd)
        if self.check_pwd() == 1:
            with open('.pi_users', 'ab') as f:
                line = bytes(self.name, encoding='utf-8') + b':' + salt + b':' + hashed_pwd + b'\n'
                f.write(line)
            return self.login()
        else:
            return 1

    def input_request(self, msg):
        """
        This method sends a question to the client, and awaits the response.


        :param msg: This is the question that the client will see.
        :type msg: str
        :return: Returns the answer to the question.
        :rtype: str
        """
        msg = 'InputRequest:' + msg
        send_file(self.sock, bytes(msg, encoding='utf-8'))
        answer = str(recv_all(self.sock), encoding='utf-8')
        return answer


class ReceivedFile:
    def __init__(self, name, ext, sock):
        """
        The ``ReceivedFile`` class creates objects of the received data from a socket, and evaluates what to do with it.


        :param name: This is the filename.
        :type name: str
        :param ext: This is the file extension.
        :type ext: str
        :param sock: This is the socket instance which is used for data transfer/reception.
        :type sock: socket.socket
        """
        self.name = name
        self.ext = ext
        self.data = b''
        self.sock = sock

    def take_data(self, data):
        """
        This method adds data to the associated filename and extension.


        :param data: Data to be added
        :type data: byte str
        """
        self.data += data

    def evaluate(self):
        """
        This method evaluates .cert, .id, and all other files with an extension.
        """
        if self.ext == 'cert':
            pass
        elif self.ext == 'id':
            if os.path.exists(self.name):  # login request from client
                user = User(self.name, str(self.data, encoding='utf-8'), self.sock)
                login = user.login()
                if login == 1:
                    logging.info('[-]  Failed login attempt by %s', self.name)
                    send_file(self.sock, b'[-]  Login attempt failed')
                elif login == 0:
                    logging.info('[+]  Successful login attempt by %s', self.name)
                    send_file(self.sock, b'[+]  Login attempt successful')
            else:  # registration request from client
                os.makedirs(self.name)
                user = User(self.name, str(self.data, encoding='utf-8'), self.sock)
                reg = user.register()
                if reg == 1:
                    logging.info('[-]  Failed registration attempt from %s', self.name)
                    send_file(self.sock, b'[-]  Registration attempt failed')
                elif reg == 0:
                    logging.info('[-]  Successful user account registration for %s', self.name)
                    send_file(self.sock, b'[+]  Registration attempt successful')
        else:
            current_user = get_cwu()
            with open(current_user + '/' + self.name+'.'+self.ext, 'wb') as f:
                f.write(self.data)


def hash_gen(pwd, salt=None):
    pwd = bytes(pwd, encoding='utf-8')
    if salt is None:
        salt = uuid.uuid4().bytes
    hashed_pwd = hashlib.pbkdf2_hmac('sha512', pwd, salt, 100000)
    return hashed_pwd, salt


def verify_hash(pwd, hashed_pwd, salt):
    possible_pwd, salt = hash_gen(pwd, salt=salt)
    return possible_pwd == hashed_pwd


def get_cwu():
    """
    This function gets the current logged-in user.


    :return: Username from the .current_user file
    :rtype: str
    """
    with open('.current_user', 'r') as f:
        return f.read()


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
        print('[+]  Sending..')
        b_data = b_data[buffer_size-1:]
    logging.info('[+]  Successfully sent data')
    return 0


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
            new_thread = threading.Thread(target=evaluate, args=(new_socket,))
            new_thread.start()
