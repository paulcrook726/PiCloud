from pycloud import *


def main():
    logging.basicConfig(format='%(asctime)s %(message)s', filename='picloud.log', level=logging.INFO)
    server = ServerSocket(46000)
    server.activate()


if __name__ == '__main__':
    main()
