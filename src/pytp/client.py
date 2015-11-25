from pytp import connectsession
from pytp import utils
import sys
import getpass
import os
import logging


class CLI:
    def __init__(self, session):
        self.session = session

    def login(self, username=''):
        if username == '':
            username = input("Please enter a username: \n")
        pwd = getpass.getpass('Please enter a password: \n')
        with open(username + '.id', 'w') as f:
            f.write(pwd)
        utils.send_encrypted_file(self.session.sock, utils.pre_proc(username + '.id'))
        self.session.listen()

    def sync(self, dir_path=''):
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
    files = []
    for (dirpath, dirnames, filenames) in os.walk(path):
        for subdirname in dirnames:
            files.append(os.path.join(dirpath, subdirname))
        for filename in filenames:
            files.append(os.path.join(dirpath, filename))
    return files


def main():
    logging.basicConfig(format='%(asctime)s %(message)s', filename='picloud.log', level=logging.INFO)
    c = connectsession.ClientSocket(connectsession.socket.gethostname(), 46000)
    address = (c.host, c.port)
    session = connectsession.ConnectionSession(c, address, is_server=False)
    interface = CLI(session)
    if sys.argv[1] == 'login':
        q = ['q', 'Q', 'quit', 'Quit', 'exit', 'Exit']
        try:
            name = sys.argv[2]
            interface.login(username=name)
        except IndexError:
            interface.login()
        print("[Press q at any time to quit]\n")
        while True:
            prompt = input()
            if prompt in q:
                utils.send_encrypted_file(session.sock, b'Logout')
                interface.session.sock.close()
                break

if __name__ == '__main__':
    main()
