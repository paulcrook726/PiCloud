from pytp import connectsession
from pytp import utils
import getpass
import os
import logging
import socket


class CLI:
    def __init__(self, session):
        """
        This class acts as a cli wrapper class for the PiCloud low-level infrastructure.


        :param session: This is the ``ConnectedSession`` class instance that the cli will use.
        :type session: connectsession.ConnectedSession
        """
        self.session = session

    def login(self, username=''):
        """
        This method initiats client login


        :param username: The username for the client
        :type username: str
        """
        if username == '':
            username = input("Please enter a username: \n")
        pwd = getpass.getpass('Please enter a password: \n')
        with open(username + '.id', 'w') as f:
            f.write(pwd)
        utils.send_encrypted_file(self.session.sock, utils.pre_proc(username + '.id'))
        self.session.listen()
        self.session.listen()

    def sync(self, dir_path=''):
        """
        This method syncs a directory with the CLI session server.


        :param dir_path: The directory path
        :type dir_path: str
        """
        if dir_path == '':
            dir_path = input('Please input the path of the directory you want to sync: \n')
        files = scan_dir(dir_path)
        dirs = []
        file_list = []
        for file in files:
            if os.path.isdir(file) is True:
                dirs.append(file)
        for file in files:
            if os.path.isfile(file) is True:
                file_list.append(file)
        for d in dirs:
            packet = b'MKDIR:' + bytes(d, encoding='utf-8')
            utils.send_encrypted_file(self.session.sock, packet)
            self.session.listen()
        for file in file_list:
            utils.send_encrypted_file(self.session.sock, utils.pre_proc(file))
            self.session.listen()


def scan_dir(path):
    """
    This function scans a path for all directories, subdirectories, and files


    :param path: Path name
    :type path: str


    :return: The files and directories located in ``path``
    :rtype: list
    """
    files = []
    for (dir_path, dir_names, file_names) in os.walk(path):
        for subdir_name in dir_names:
            files.append(os.path.join(dir_path, subdir_name))
        for filename in file_names:
            files.append(os.path.join(dir_path, filename))
    return files


def main():
    """
    The main cli function.  Used for gathering terminal input at program initiation.  Start via picli.
    """
    wd = os.path.join(os.path.expanduser('~'), 'pInteClient')
    print(wd)
    os.makedirs(wd, exist_ok=True)
    os.chdir(wd)
    logging.basicConfig(format='%(asctime)s %(message)s', filename='pInteServ.log', level=logging.INFO)
    port = None
    hostname = None
    while hostname is None:
        hostname = input("Please input your server/host ip address, or press q to quit.\n"
                         "Typing nothing and pressing enter will look for a server on this computer.\n")
        if hostname == 'q':
            return 0
        elif hostname == '':
            hostname = socket.gethostname()
    while port is None:
        port = int(input("Please input the port number you would like to listen on, or press q to quit.\n"))
        if port == 'q':
            return 0
    c = connectsession.ClientSocket(hostname, port)
    address = (c.host, c.port)
    session = connectsession.ConnectionSession(c, address, is_server=False)
    interface = CLI(session)
    print("[Press q at any time to quit]\n")
    prompt = None
    while prompt != 'q':
        prompt = input()
        if prompt == 'login':
            print("Logging in...\n")
            interface.login()
            print("Done!")
        if prompt == 'sync':
            path = input("Please specify the path of the directory you would like to keep synced.\n")
            interface.sync(dir_path=path)
    print("Bye!")
    utils.send_encrypted_file(session.sock, b'Logout')
    interface.session.sock.close()

if __name__ == '__main__':
    main()
