"""
This module is the primary building block of the PyCloud infrastructure.  Within it, the basic file transfer protocol is
laid down.
"""
import socket
import threading
import os
import logging
import nacl.public
import nacl.encoding
import nacl.utils
from pytp import utils


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
        utils.hex_keygen()
        utils.process_key_file(utils.recv_all(self.sock))
        utils.send_file(self.sock, utils.pre_proc('.public.key', is_server=1))
        while self.listen() == 0:
            pass

    def client(self):
        utils.hex_keygen()
        utils.send_file(self.sock, utils.pre_proc('.public.key'))
        utils.process_key_file(utils.recv_all(self.sock))

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
            utils.send_encrypted_file(self.sock, b'FileReceived')
            file_data = file_list[0]
            return self.evaluate_contents(file_data)
        else:
            logging.info('[-]  File Request')
            utils.send_encrypted_file(self.sock, utils.pre_proc((self.filename + self.ext), is_server=1))
            return 0

    def evaluate_contents(self, file_data):
        if self.ext == 'id':
            self.username = self.filename
            self.pwd = file_data
            if os.path.exists(self.username) is True:  # login request from client
                log_in = self.login()
                if log_in == 1:
                    logging.info('[-]  Failed login attempt by %s', self.username)
                    utils.send_encrypted_file(self.sock, b'[-]  Login attempt failed')
                    return log_in
                elif log_in == 0:
                    logging.info('[+]  Successful login attempt by %s', self.username)
                    utils.send_encrypted_file(self.sock, b'[+]  Login attempt successful')
                    return log_in
            else:  # registration request from client
                os.makedirs(self.username)
                reg = self.register()
                if reg == 1:
                    logging.info('[-]  Failed registration attempt from %s', self.username)
                    utils.send_encrypted_file(self.sock, b'[-]  Registration attempt failed')
                    return reg
                elif reg == 0:
                    logging.info('[-]  Successful user account registration for %s', self.username)
                    utils.send_encrypted_file(self.sock, b'[+]  Registration attempt successful')
                    return reg
        else:
            current_user = self.username
            try:
                with open(current_user + self.filename + '.' + self.ext, 'wb') as f:
                    f.write(file_data)
            except IsADirectoryError:
                pass
            return 0

    def listen(self):
        encrypted_msg = utils.recv_all(self.sock)
        if encrypted_msg is None:
            return 1
        private_key = utils.get_private_key()
        public_key = utils.get_other_public_key()
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
                utils.send_encrypted_file(self.sock, bytes(answer, encoding='utf-8'))
                return 0
            elif msg == b'Logout':
                logging.info('[-]  Client session logging out')
                utils.send_encrypted_file(self.sock, b'Logout')
                self.sock.close()
                return 1
            elif msg.split(b':')[0] == b'MKDIR':
                user_folder = self.username
                os.makedirs(user_folder + msg.split(b':')[1].decode(encoding='utf-8'), exist_ok=True)
                logging.info('[+]  Successfully synced directory.')
                utils.send_encrypted_file(self.sock, b'FileReceived')
                return 0

    def login(self):
        raw_pwd, salt = utils.get_usr_pwd(self.username)
        msg = 'Incorrect username or password.\n' \
              '[1] Exit\n' \
              '[2] Register an account under this name and password\n'
        if raw_pwd == 1:
            answ = self.input_request(msg)
            if answ == '1':
                return 1
            elif answ == '2':
                return self.register()
        if utils.verify_hash(self.pwd, raw_pwd, salt=salt) is True:
            return 0
        else:
            answ = self.input_request(msg)
            if answ == '1':
                return 1
            elif answ == '2':
                return self.register()

    def input_request(self, msg):
        msg = 'InputRequest:' + msg
        utils.send_encrypted_file(self.sock, bytes(msg, encoding='utf-8'))
        answer = str(utils.recv_all(self.sock), encoding='utf-8')
        return answer

    def register(self):
        hashed_pwd, salt = utils.hash_gen(self.pwd)
        if utils.get_usr_pwd(self.username) == 1:
            with open('.pi_users', 'ab') as f:
                line = bytes(self.username, encoding='utf-8') + b':' + salt + b':' + hashed_pwd + b'\n'
                f.write(line)
            return self.login()
        else:
            return 1
