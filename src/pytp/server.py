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
    server = connectsession.ServerSocket(46000)
    server.activate()

if __name__ == '__main__':
    main()