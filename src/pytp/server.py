from pytp import connectsession
import logging


def main():
    """
    The main function for starting a server.  Usage is piserver
    """
    logging.basicConfig(format='%(asctime)s %(message)s', filename='picloud.log', level=logging.INFO)
    server = connectsession.ServerSocket(46000)
    server.activate()
