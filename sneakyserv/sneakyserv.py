from concurrent.futures import FIRST_EXCEPTION, ThreadPoolExecutor, wait, FIRST_COMPLETED
from abc import ABC, abstractmethod
from collections import namedtuple
from datetime import datetime
import argparse
import socket
import sys

class HandleClients(ABC):
    ClientInfo = namedtuple('ClientInfo', ['cli_type', 'sock', 'info'])

    def __init__(self, args):
        self.first_cli_type = None
        self.socks_info = list()
        self.running = False
        self.args = args

    @abstractmethod
    def setup_conns(self): pass

    def print_status(self, client_info, msg):
        formatted_current_time = datetime.now().strftime('%H:%M:%S')
        print(f'[{formatted_current_time}][{client_info.cli_type}] => {hex(id((client_info.sock)))} => {client_info.info[0]}:{client_info.info[1]} {msg}')

    def handle_client(self, local_sock, remote_sock):
        executor = ThreadPoolExecutor(max_workers=2)
        futures = (
            executor.submit(self.send_and_recv, local_sock, remote_sock),
            executor.submit(self.send_and_recv, remote_sock, local_sock)
        )
        wait(futures, return_when=FIRST_COMPLETED)
        executor.shutdown(wait=False)

    def send_and_recv(self, send_sock, recv_sock):
        while (data := recv_sock.recv(self.args.buff_size)) and data != b'': send_sock.send(data)

    def close_all_socks(self):
        for client_info in self.socks_info:
            try:
                if client_info.sock is None: continue
                client_info.sock.shutdown(socket.SHUT_RDWR)
                self.print_status(client_info, 'disconnected')
            except OSError: pass

    def request_shutdown(self):
        if self.running: self.close_all_socks()

    def run(self):
        try:
            self.running = True
            self.setup_conns()
        finally:
            self.running = False
            self.close_all_socks()

    def handle_clients(self, serv_sock):
        self.sock, self.sock_info = serv_sock.accept()
        client_info = self.ClientInfo(sock=self.sock, info=self.sock_info, cli_type=self.first_cli_type)
        self.print_status(client_info, 'connected')
        self.socks_info.append(client_info)
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(self.run)
        executor.shutdown(wait=False, cancel_futures=False)
        return future

class RecvMode(HandleClients):
    def __init__(self, args):
        super().__init__(args)
        self.first_cli_type = 'remote'

    def setup_conns(self):
        remote_client_sock = self.sock
        def auth():
            passw_count = len(self.args.passw)
            bytes_left = 255
            passw = ''
            while (chunk := remote_client_sock.recv(bytes_left).decode()) and bytes_left != 0:
                if chunk == '': return
                bytes_left -= len(chunk)
                eol_index = chunk.find('\n')
                if eol_index != -1:
                    if passw + chunk[0:eol_index + 1] == self.args.passw:
                        local_client_sock = socket.create_connection((self.args.rhost, self.args.rport), timeout=self.args.lhost_timeout)
                        client_info = self.ClientInfo(sock=local_client_sock, info=local_client_sock.getsockname(), cli_type='local')
                        self.socks_info.append(client_info)
                        self.print_status(client_info, 'connected')
                        local_client_sock.send(chunk[eol_index + 1:-1].encode())
                        return local_client_sock
                    else: return
                passw += chunk
        executor = ThreadPoolExecutor(max_workers=1)
        auth_worker = executor.submit(auth)
        try:
            if (local_client_sock := auth_worker.result(timeout=self.args.auth_timeout)) and local_client_sock is None: return
        except TimeoutError: return
        else:
            remote_client_sock.settimeout(self.args.rhost_timeout)
            self.handle_client(local_client_sock, remote_client_sock)

class SendMode(HandleClients):
    def __init__(self, args):
        super().__init__(args)
        self.first_cli_type = 'local'

    def setup_conns(self):
        local_client_sock = self.sock
        local_client_sock.settimeout(self.args.lhost_timeout)
        remote_client_sock = socket.create_connection((self.args.rhost, self.args.rport), timeout=self.args.rhost_timeout)
        client_info = self.ClientInfo(sock=remote_client_sock, info=remote_client_sock.getsockname(), cli_type='remote')
        self.socks_info.append(client_info)
        self.print_status(client_info, 'connected')
        remote_client_sock.send(self.args.passw.encode())
        self.handle_client(local_client_sock, remote_client_sock)

# TODO:
    # Prettify main
def main():
    def __passw(passw):
        eol_count = passw.count('\n')
        if eol_count > 1: raise argparse.ArgumentTypeError('Passw may contain at most one newline character, and it must be at the end.')
        elif not passw.endswith('\n'): passw += '\n'
        return passw

    parser = argparse.ArgumentParser(description='SneakySSH - Obfuscator for SSH connections.')
    parser.add_argument('--rhost', '-r', required=True, help='The remote IP address to connect to.')
    parser.add_argument('--lhost', '-l', required=True, help='The IP address to listen on.')
    parser.add_argument('--passw', '-p', required=True, type=__passw, help='The banner/password to send/receive (depending on the mode).')

    default_timeout = socket.getdefaulttimeout()
    parser.add_argument('--lhost-timeout', dest='lhost_timeout', type=float, default=default_timeout, help='The timeout for incoming connections (in seconds).')
    parser.add_argument('--rhost-timeout', dest='rhost_timeout', type=float, default=default_timeout, help='The timeout for connections to the remote server (in seconds).')

    parser.add_argument('--client-limit', dest='client_limit', type=int, default=3, help='The maximum number of clients that can be accepted.')
    parser.add_argument('--auth-timeout', dest='auth_timeout', type=float, default=2.5, help='The authentication timeout (in seconds).')

    parser.add_argument('--rport', '--rp', type=int, default=9999, help='The port of the remote server.')
    parser.add_argument('--lport', '--lp', type=int, default=9999, help='The port to listen on.')

    parser.add_argument('--buff-size', dest='buff_size', type=int, default=2048, help='The buffer size for recv/send.')

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--recv', action='store_true', help='Receive mode: wait for connections, and if the password is correct, forward everything to the server.')
    mode.add_argument('--send', action='store_true', help='Send mode: send the password first, then forward all data from a specific network program to the server.')
    # mode.add_argument('--proxy', action='store_true', help='Not implemented.')

    # TODO:
        # Add "proxy" mode
        # Add "verbose" mode
        # Add "encrypted" mode (maybe)
        # Add secret passw

    args = parser.parse_args()
    if args.recv: client_handler_class = RecvMode
    else: client_handler_class = SendMode

    with ThreadPoolExecutor(max_workers=args.client_limit) as executor:
        client_handlers = []
        futures = []
        serv_sock = None
        try:
            serv_sock = socket.create_server((args.lhost, args.lport), reuse_port=True)
            serv_sock.listen()
            while True:
                client_handler = client_handler_class(args)
                client_handlers.append(client_handler)
                futures.append(client_handler.handle_clients(serv_sock))
                if len(futures) >= args.client_limit: wait(futures, return_when=FIRST_COMPLETED)
                for future in futures:
                    if not future.done(): continue
                    i = futures.index(future)
                    client_handlers[i].request_shutdown()
                    client_handlers.pop(i)
                    futures.pop(i)
        except (KeyboardInterrupt, EOFError): print()
        finally:
            if serv_sock is not None: serv_sock.close()
            for client_handler in client_handlers: client_handler.request_shutdown()
            sys.exit(120)

if __name__ == '__main__': main()
