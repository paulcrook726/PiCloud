from pytp import connectsession
import logging
import os


def main():
    """
    The main function for starting a server.  Usage is piserver
    """
    wd = os.path.join(os.path.expanduser('~'), 'pInteServer')
    os.makedirs(wd, exist_ok=True)
    os.chdir(wd)
    logging.basicConfig(format='%(asctime)s %(message)s', filename='pInteServ.log', level=logging.INFO)
    port = None
    while port is None:
        port = input("Please input the port number you would like to listen on, or press q to quit.\n")
        if port == 'q':
            return 0
    server = connectsession.ServerSocket(port)
    server.activate()

if __name__ == '__main__':
    main()
