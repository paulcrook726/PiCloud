"""
This module is the primary building block of the PyCloud infrastructure.  Within it, the basic file transfer protocol is
laid down.
"""
import socket
import struct
import threading
import os
import logging


class SentFile:
    def __init__(self, name, ext):
        self.name = name
        self.ext = ext
        self.data = b''

    def take_data(self, data):
        self.data += data

    def evaluate(self):
        if self.ext == 'id':
            something = ''
        else:
            with open(self.name+'.'+self.ext, 'wb') as f:
                f.write(self.data)


def recv_all(client_sock):
    """
    A helper function for ``proc_block()``.  Computes message length and splits into 2mb blocks,
    then calls ``proc_block``.
    :param client_sock: The socket which is receiving data.
    :type client_sock: socket.socket
    :returns: None if ``raw_len`` is None.

    """
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
    """
    The ``send_file`` function appends the length of a file to the end of the data, and sends it on a socket.

    Args:
        :param sock: The socket which sends the file.
        :type sock: socket.socket
        :param b_data: The byte string data to be sent.
        :type b_data: byte str

    """
    length = len(b_data)
    b_data = struct.pack('>I', length) + b_data
    sent = 0
    buffer_size = 1024**2
    while sent < length:
        to_send = b_data[:buffer_size-1]
        just_sent = sock.send(to_send)
        sent += just_sent
        print('[+]  Upload %i% complete', ((sent/length)*100))
        b_data = b_data[buffer_size-1:]
    logging.info('[+]  Successfully sent data')


def evaluate(sock):
    """
    This function takes a socket and receives the incoming and evaluates it based on its features.

    If a normal file is received, the socket sends of a confirmation message, and then inputs the file into a SentFile
    object instance.  If the received data is just a name, it assumes a request is being made, queries the name
    for processing, and, if the filename exists on the local filesystem, sends the corresponding file back to the peer
    socket.

        Args:
            :param sock: The socket which receives the data.
            :type sock: socket.socket
            :returns: ``sock.close()`` or only ends.

    """
    (ip, port) = sock.getpeername()
    data = recv_all(sock)
    if data == b'FileError':
        logging.info('[-]  Request could not be found')
        return sock.close()
    if data == b'FileReceived':
        logging.info('[+]  Sent file was successfully received')
        return sock.close()
    if data is None:
        return sock.close()
    data = data.split(b'::::::::::')
    logging.info('[+]  Received data from: %s:%i', ip, port)
    try:
        x = data[-4]
        logging.info("[-]  Delimiter has been found in multiple areas, causing %i bytes to be left out.  "
                     "This causes incomplete file writes.  Exiting now!", len(x))

        return sock.close()
    except IndexError:
        pass
    file_ext = str(data[-1], encoding='utf-8')
    name = str(data[-2], encoding='utf-8')
    logging.info('[+]  The file %s.%s was received.', name, file_ext)
    if len(data) > 2:
        send_file(sock, b'FileReceived')
        sock.close()
        data = data[-3]
        file = SentFile(name, file_ext)
        file.take_data(data)
        file.evaluate()
    else:
        logging.info('[-]  File Request')
        send_file(sock, pre_proc((name+'.'+file_ext), is_server=1))


def pre_proc(filename, is_server=0):
    """The ''pre_proc'' function processes a filename, and returning the answer.

    If the filename exists in the local filesystem, then the corresponding file is read into byte string, processed, and
    returned.

        Args:
            :param filename: Name of the file to be pre-processed.
            :type filename: str
            :param is_server: This flags the function as being used on a server.
            :type is_server: int
            :returns: Either file data, file name, or ``FileError``.
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



