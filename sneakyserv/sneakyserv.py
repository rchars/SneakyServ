from concurrent.futures import ThreadPoolExecutor, as_completed
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

    def _setup_conns(self): return self._setup_conns_hook(self)

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
        try: self._setup_conns()
        finally: self.close_all_socks()

def _recv_mode(inst):
    inst._remote_client_sock = inst._sock
    passw_count = len(inst._args.passw)
    bytes_left = 255
    passw = ''
    while (chunk := inst._remote_client_sock.recv(bytes_left).decode()) and bytes_left != 0:
        if chunk == '': return
        bytes_left -= len(chunk)
        eol_index = chunk.find('\n')
        if eol_index != -1:
            if passw + chunk[0:eol_index] == inst._args.passw:
                inst._local_client_sock = socket.create_connection((inst._args.rhost, inst._args.rport), timeout=inst._args.rhost_timeout)
                inst._local_client_sock.send(chunk[eol_index + 1:-1].encode())
                inst._handle_client(inst._local_client_sock, inst._remote_client_sock)
                return
            else: return
        passw += chunk
    return

def _send_mode(inst):
        inst._local_client_sock = inst._sock
        inst._remote_client_sock = socket.create_connection((inst._args.rhost, inst._args.rport), timeout=inst._args.rhost_timeout)
        inst._remote_client_sock.send(inst._args.passw.encode())
        inst._handle_client(inst._local_client_sock, inst._remote_client_sock)

# TODO:
    # Prettify main
def main():
    parser = argparse.ArgumentParser(description='SneakySSH - Obfuscator for SSH connections.')
    parser.add_argument('--rhost', '-r', required=True, help='The remote IP address to connect to.')
    parser.add_argument('--lhost', '-l', required=True, help='The IP address to listen on.')
    parser.add_argument('--passw', '-p', required=True, help='The banner/password to send/receive (depending on the mode).')

    default_timeout = socket.getdefaulttimeout()
    parser.add_argument('--lhost-timeout', dest='lhost_timeout', type=float, default=default_timeout, help='The timeout for incoming connections (in seconds).')
    parser.add_argument('--rhost-timeout', dest='rhost_timeout', type=float, default=default_timeout, help='The timeout for connections to the remote server (in seconds).')
    parser.add_argument('--client-limit', dest='client_limit', type=int, default=3, help='The maximum number of clients that can be accepted.')

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
        futures = []
        client_handlers = []
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
                if len(futures) != args.client_limit: continue
                for future in as_completed(futures):
                    result = future.result()
                    i = futures.index(future)
                    futures.pop(i)
                    client_handlers.pop(i)
        except (KeyboardInterrupt, EOFError):
            for client_handler in client_handlers:
                client_handler.close_all_socks()
            print()
            sys.exit(120)
        finally:
            if serv_sock is not None: serv_sock.close()

if __name__ == '__main__': main()
