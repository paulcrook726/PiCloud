from pycloud import *


def main():
    logging.basicConfig(format='%(asctime)s %(message)s', filename='picloud.log', level=logging.INFO)
    c = ClientSocket('192.168.2.194', 46000)
    f = pre_proc('read.pdf')
    send_file(c, f)
    while evaluate(c) == 0:
        pass

if __name__ == '__main__':
    main()
