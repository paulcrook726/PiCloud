from pytp import connectsession
import logging
import os


def main():
    """
    The main function for starting a server.  Usage is piserver
    """
    wd = os.path.join(os.path.expanduser('~'), 'pInteServ')
    os.makedirs(wd)
    os.chdir(wd)
    logging.basicConfig(format='%(asctime)s %(message)s', filename='pInteServ.log', level=logging.INFO)
    server = connectsession.ServerSocket(46000)
    server.activate()
