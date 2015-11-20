import argparse


def main():
    parser = argparse.ArgumentParser(description='Options for using pi-cli.')
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='Show logging info.[Default]')
    parser.add_argument('-u',
                        action='store_true',
                        help='This returns your current working user id.')
    args = parser.parse_args()
    if args.u is True:
        show_user_id()

if __name__ == '__main__':
    main()
