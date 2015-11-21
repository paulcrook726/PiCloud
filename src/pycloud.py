"""
This module is the primary building block of the PyCloud infrastructure.  Within it, the basic file transfer protocol is
laid down.
"""
import socket
import struct
import threading
import os
import logging
import crypt


class User:
    def __init__(self, name, pwd, sock):
        """

        :param name:
        :type name:
        :param pwd:
        :type pwd:
        :param sock:
        :type sock:
        :return:
        :rtype:
        """
        self.name = name
        self.pwd = pwd
        self.sock = sock

    def make_hashed(self, salt=None):
        """

        :param salt:
        :type salt:
        :return:
        :rtype:
        """
        if salt is None:
            salt = crypt.mksalt(crypt.METHOD_SHA512)
            hashed_pwd = crypt.crypt(self.pwd, salt)
            return hashed_pwd
        else:
            hashed_pwd = crypt.crypt(self.pwd, salt)
            return hashed_pwd

    def check_pwd(self):
        """

        :return:
        :rtype:
        """
        with open('.pi_users', 'a+') as f:
            f.seek(0)
            for line in f:
                line_list = line.split(':')
                if self.name == line_list[0]:
                    raw_pwd = line_list[1].strip('\n')
                    return raw_pwd
                else:
                    pass
            return 1

    def login(self):
        """

        :return:
        :rtype:
        """
        raw_pwd = self.check_pwd()
        msg = 'Incorrect username or password.\n' \
              '[1] Exit\n' \
              '[2] Register an account under this name and password\n'
        if raw_pwd == 1:
            answ = self.input_request(msg)
            if answ == '1':
                pass
            elif answ == '2':
                self.register()
            return 1
        hashed_pwd = self.make_hashed(salt=raw_pwd)
        if raw_pwd == hashed_pwd:
            with open('.current_user', 'w') as f:
                f.write(self.name)

            return 0
        else:
            answ = self.input_request(msg)
            if answ == '1':
                pass
            elif answ == '2':
                self.register()
            return 1

    def register(self):
        """

        :return:
        :rtype:
        """
        hashed_pwd = self.make_hashed()
        if self.check_pwd() == 1:
            with open('.pi_users', 'a') as f:
                line = self.name + ':' + hashed_pwd + '\n'
                f.write(line)
            return self.login()
        else:
            return 1

    def input_request(self, msg):
        msg = 'InputRequest:' + msg
        send_file(self.sock, bytes(msg, encoding='utf-8'))
        answer = str(recv_all(self.sock), encoding='utf-8')
        return answer


class ReceivedFile:
    def __init__(self, name, ext, sock):
        """

        :param name:
        :type name:
        :param ext:
        :type ext:
        :param sock:
        :type sock:
        :return:
        :rtype:
        """
        self.name = name
        self.ext = ext
        self.data = b''
        self.sock = sock

    def take_data(self, data):
        """

        :param data:
        :type data:
        :return:
        :rtype:
        """
        self.data += data

    def evaluate(self):
        """

        :return:
        :rtype:
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


def get_cwu():
    """

    :return:
    :rtype:
    """
    with open('.current_user', 'r') as f:
        return f.read()


def recv_all(client_sock):
    """

    :param client_sock:
    :type client_sock:
    :return:
    :rtype:
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

    :param client_sock:
    :type client_sock:
    :param length:
    :type length:
    :return:
    :rtype:
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

    :param sock:
    :type sock:
    :param b_data:
    :type b_data:
    :return:
    :rtype:
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


def evaluate(sock):
    """

    :param sock:
    :type sock:
    :return:
    :rtype:
    """
    (ip, port) = sock.getpeername()
    data = recv_all(sock)
    if b'::::::::::' in data:  # indicated that the data is a filename (possibly only a request for a filename)
        data = data.split(b'::::::::::')  # split data along delimiter
        logging.info('[+]  Received data from: %s:%i', ip, port)
        try:  # check if delimiter exists in data.  If this happens, the data will be compromised.
            x = data[-4]
            logging.info("[-]  Delimiter has been found in multiple areas, causing %i bytes to be left out.  "
                         "This causes incomplete file writes.  Exiting now!", len(x))
            sock.close()
            return 1
        except IndexError:
            pass
        file_ext = str(data[-1], encoding='utf-8')
        name = str(data[-2], encoding='utf-8')
        logging.info('[+]  The file %s.%s was received.', name, file_ext)
        if len(data) > 2:
            send_file(sock, b'FileReceived')
            data = data[-3]
            file = ReceivedFile(name, file_ext, sock)
            file.take_data(data)
            file.evaluate()
            return 0
        else:
            logging.info('[-]  File Request')
            send_file(sock, pre_proc((name+'.'+file_ext), is_server=1))
            return 0
    else:  # data is a small message used in the transfer protocol
        if data == b'FileError':
            logging.info('[-]  Request could not be found')
            sock.close()
            return 1
        elif data == b'FileReceived':
            logging.info('[+]  Sent file was successfully received')
            return 0
        elif data is None:
            sock.close()
            return 1
        elif data.split(b':')[0] == b'InputRequest':

            answer = input(str(data.split(b':')[1], encoding='utf-8'))
            send_file(sock, bytes(answer, encoding='utf-8'))
            return 0
        else:
            logging.info(str(data, encoding='utf-8'))


def pre_proc(filename, is_server=0):
    """

    :param filename:
    :type filename:
    :param is_server:
    :type is_server:
    :return:
    :rtype:
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
        #  This structures the byte string into data<>name<>file extension.  This will later be
        #  decoded in order to store the data under the name and file extension.
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

        Args:
            :param host: Host IP or hostname of desired peer socket.
            :type host: str
            :param port: Port number of server service.
            :type port: int
            :returns:

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

        Args:
            :param port: Port number to listen on.
            :type port: int
            :returns:

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
