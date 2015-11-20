import getpass
import crypt
import sys

verbose = False


def check_pwd(name):
    """

    :param name:
    :type name:
    :return:
    :rtype:
    """
    with open('.pi_users', 'r') as f:
        for line in f:
            line_list = line.split(':')
            if name == line_list[0]:
                raw_pwd = line_list[1].split('$')
                pwd = raw_pwd[2]
                salt = raw_pwd[1]
                return pwd, salt
            else:
                pass
        return 1


def salted_hash(pwd, salt=None):
    """

    :param pwd:
    :type pwd:
    :param salt:
    :type salt:
    :return:
    :rtype:
    """
    if salt is None:
        salt = crypt.mksalt(crypt.METHOD_SHA512)
    hashed_pwd = crypt.crypt(pwd, salt)
    return hashed_pwd


def get_info():
    """

    :return:
    :rtype:
    """
    name = input("Please enter you username: ")
    pwd = getpass.getpass("\nPlease enter you password: ")
    return name, pwd


def false_pwd_usr():
    """

    :return:
    :rtype:
    """
    q = input('Username or password is false.\n'
              '[1] Try again\n'
              '[2] Exit\n')
    if q == '1':
        return setup(query='1')
    elif q == '2':
        return sys.exit(1)
    else:
        return sys.exit(1)


def login(name, pwd):
    """

    :param name:
    :type name:
    :param pwd:
    :type pwd:
    :return:
    :rtype:
    """
    try:
        (stored_pwd, salt) = check_pwd(name)
    except check_pwd(name) == 1:
        return false_pwd_usr()
    hashed_pwd = salted_hash(pwd, salt)
    if stored_pwd == hashed_pwd:
        with open('.current_user', 'w') as f:
            f.write(name)
        return 0
    else:
        return false_pwd_usr()


def register(name, pwd):
    """

    :param name:
    :type name:
    :param pwd:
    :type pwd:
    :return:
    :rtype:
    """
    hashed_pwd = salted_hash(pwd)
    if check_pwd(name) == 1:
        with open('.pi_users', 'a') as f:
            line = name + ':' + hashed_pwd + '\n'
            f.write(line)
        return login(name, pwd)
    else:
        query = input("Your username is already used.  Would you like to:\n"
                      "[1] Try to login?\n"
                      "[2] Register under a different username?\n")
        if query == '1':
            return login(name, pwd)
        elif query == '2':
            return setup(query='2')
        else:
            print('Incorrect answer.  Trying again')
            return register(name, pwd)


def setup(query=''):
    """

    :param query:
    :type query:
    :return:
    :rtype:
    """
    if query == '':
        query = input("Hello and welcome to Picloud.\n"
                      "[1] Login\n"
                      "[2] Register\n"
                      "[3] Run a server\n\n"
                      "Please select an option.\n")
    if query == '1':
        (name, pwd) = get_info()
        return login(name, pwd)
    elif query == '2':
        (name, pwd) = get_info()
        test = getpass.getpass("\nPlease confirm your password: ")
        if pwd == test:
            return register(name, pwd)
        else:
            print("Passwords did not match!  Please retry.")
            return setup(query='2')
    elif query == '3':
        start_server()


def main():
    setup()

if __name__ == '__main__':
    main()
