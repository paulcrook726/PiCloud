import hashlib
import uuid
import struct
import socket
import os
import logging
import nacl.public
import nacl.encoding
import nacl.utils


def hash_gen(pwd, salt=None):
    """
    This function generates a hashed password from a given pwd.  If specified, a particule salt will be used; otherwise,
    the salt is randomly generated.


    :param pwd: The password to be hashed
    :type pwd: str or bytes
    :param salt: The salt to be used for hash gen.
    :type salt: bytes


    :return: Returns the hashed password and salt
    :rtype: bytes
    """
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
    """
    This simply verifies a password with a particular salt with an already hashed password.  Used for user login.


    :param pwd: Unhashed password
    :type pwd: str
    :param hashed_pwd: The stored, already hashed password.
    :type hashed_pwd: bytes
    :param salt: The salt used for the hashed password
    :type salt: bytes


    :return: True or False, depending on the verification
    :rtype: Boolean
    """
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
    """
    This function encryptes data to be sent.
    :param sock: The socket used to send data
    :type sock: socket.socket
    :param b_data: The data to be sent
    :type b_data: bytes


    :return: The return value of ``send_file``, 0 on success
    :rtype: int
    """
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
        file_ext = b''
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
    """
    This generates a paired public/private key pair.  Used for the secure handshake.
    """
    private_key = nacl.public.PrivateKey.generate()
    public_key = private_key.public_key
    private_key = private_key.encode(encoder=nacl.encoding.HexEncoder)
    public_key = public_key.encode(encoder=nacl.encoding.HexEncoder)
    with open('.public.key', 'wb') as f:
        f.write(public_key)
    with open('.private.key', 'wb') as t:
        t.write(private_key)


def get_usr_pwd(username):
    """
    This checks the main user password file and gets a particular user's password.


    :param username: The username who's password is to be retrieved.
    :type username: str


    :return: Returns the byte password and salt
    :rtype: bytes
    """
    with open('.users.txt', 'ab+') as f:
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
    """
    This simply gets the public key of the connected socket.

    :return: Returns the public key
    :rtype: bytes(hex)
    """
    with open('.otherpublic.key', 'r+b') as f:
        public_key = f.readline()
    public_key = public_key.split(b'::::::::::')[0]
    return nacl.public.PublicKey(public_key, encoder=nacl.encoding.HexEncoder)


def get_private_key():
    """
    This gets the private key of the client/server by reading the secret file.


    :return: Returns the private key
    :rtype: bytes(hex)
    """
    with open('.private.key', 'r+b') as f:
        private_key = f.readline()
    return nacl.public.PrivateKey(private_key, encoder=nacl.encoding.HexEncoder)


def process_key_file(key_file):
    """
    This creates the connected socket's public key file.


    :param key_file: The key data
    :type key_file: bytes(hex)
    """
    with open('.otherpublic.key', 'w+b') as file:
        file.write(key_file)
