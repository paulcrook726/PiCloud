from server import *

def main():
    logging.basicConfig(format='%(asctime)s %(message)s', filename='picloud.log', level=logging.INFO)
    c = ClientSocket('192.168.2.194', 46000)
    f = pre_proc('random.txt')
    send_file(c, f)
    print(str(recv_all(c), encoding='utf-8'))


if __name__ == '__main__':
    main()
