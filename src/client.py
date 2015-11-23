from pycloud import *


def main():
    logging.basicConfig(format='%(asctime)s %(message)s', filename='picloud.log', level=logging.INFO)
    c = ClientSocket(socket.gethostname(), 46000)
    f = pre_proc('file.something')
    send_file(c, f)
    while evaluate(c) == 0:
        pass

if __name__ == '__main__':
    main()
