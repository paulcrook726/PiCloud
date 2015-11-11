from server import *

def main():
    logging.basicConfig(format='%(asctime)s %(message)s', filename='picloud.log', level=logging.INFO)
    c = ClientSocket('192.168.2.194', 46000)
    f = pre_proc('dsja.jd')
    send_file(c, f)
    evaluate(c)


if __name__ == '__main__':
    main()
