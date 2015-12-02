from setuptools import setup, find_packages


def readme():
    with open('./README.rst') as f:
        return f.read()

setup(name='pInteServ',
      version='0.111',
      description='Module and cli for client/server directory sync.',
      long_description=readme(),
      url='https://github.com/paulcrook726/PiCloud.git',
      author='Paul Crook',
      author_email='paulcrook726@gmail.com',
      license='GNU',
      entry_points={
          'console_scripts':
              ['picli = pytp.client_cli:main',
               'piserver = pytp.server:main'],
      },
      packages=find_packages(),
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Programming Language :: Python :: 3.5',
          'Topic :: Internet :: File Transfer Protocol (FTP)',
      ],
      install_requires=[
          'pynacl',]
      )
