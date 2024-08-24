from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import threading
import argparse
import socket
import sys

class HandleClients(threading.Thread):
    def __init__(self, args, sock, hook):
        super().__init__()
        self._remote_client_sock = None
        self._local_client_sock = None
        self._setup_conns_hook = hook
        self._sock = sock
        self._args = args

    def _handle_client(self, local_sock, remote_sock):
        t_1 = threading.Thread(target=self._send_and_recv, args=(local_sock, remote_sock,))
        t_2 = threading.Thread(target=self._send_and_recv, args=(remote_sock, local_sock,))
        t_1.start()
        t_2.start()
        t_1.join()

    def _send_and_recv(self, send_sock, recv_sock):
        while (data := recv_sock.recv(1024)) and data != b'': send_sock.send(data)

    def close_all_socks(self):
        for sock in (self._remote_client_sock, self._local_client_sock):
            try:
                if sock is not None: sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass

    def run(self):
        try: self._setup_conns_hook(self)
        finally: self.close_all_socks()

def _recv_mode(inst):
    inst._remote_client_sock = inst._sock
    is_authed = threading.Event()
    def auth():
        passw_count = len(inst._args.passw)
        bytes_left = 255
        passw = ''
        while (chunk := inst._remote_client_sock.recv(bytes_left).decode()) and bytes_left != 0:
            if chunk == '': return
            bytes_left -= len(chunk)
            eol_index = chunk.find('\n')
            if eol_index != -1:
                if passw + chunk[0:eol_index + 1] == inst._args.passw:
                    inst._local_client_sock = socket.create_connection((inst._args.rhost, inst._args.rport), timeout=inst._args.rhost_timeout)
                    inst._local_client_sock.send(chunk[eol_index + 1:-1].encode())
                    is_authed.set()
                    return
                else: return
            passw += chunk
    auth_thread = threading.Thread(target=auth)
    auth_thread.start()
    auth_thread.join(inst._args.auth_timeout)
    if not auth_thread.is_alive() and is_authed.is_set():
        inst._remote_client_sock.settimeout(inst._args.rhost_timeout)
        inst._handle_client(inst._local_client_sock, inst._remote_client_sock)

def _send_mode(inst):
        inst._local_client_sock = inst._sock
        inst._remote_client_sock = socket.create_connection((inst._args.rhost, inst._args.rport), timeout=inst._args.rhost_timeout)
        inst._remote_client_sock.send(inst._args.passw.encode())
        inst._handle_client(inst._local_client_sock, inst._remote_client_sock)

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
    parser. add_argument('--auth-timeout', dest='auth_timeout', type=float, default=2.5, help='The authentication timeout (in seconds).')

    parser.add_argument('--rport', '--rp', type=int, default=9999, help='The port of the remote server.')
    parser.add_argument('--lport', '--lp', type=int, default=9999, help='The port to listen on.')

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
    with ThreadPoolExecutor(max_workers=args.client_limit) as executor:
        client_handlers = []
        futures = []
        serv_sock = None
        hook = None
        if args.recv: hook = _recv_mode
        else: hook = _send_mode
        try:
            serv_sock = socket.create_server((args.lhost, args.lport), reuse_port=True)
            serv_sock.settimeout(args.lhost_timeout)
            serv_sock.listen()
            while True:
                sock = serv_sock.accept()[0]
                client_handler = HandleClients(args, sock, hook)
                client_handlers.append(client_handler)
                futures.append(executor.submit(client_handler.run))
                if len(futures) >= args.client_limit:
                    wait(futures, return_when=FIRST_COMPLETED)
                for future in futures:
                    if not future.done(): continue
                    i = futures.index(future)
                    client_handlers.pop(i)
                    futures.pop(i)
        except (KeyboardInterrupt, EOFError): print()
        finally:
            if serv_sock is not None: serv_sock.close()
            for client_handler in client_handlers:
                client_handler.close_all_socks()
            for future in futures: future.cancel()
            sys.exit(120)

if __name__ == '__main__': main()
