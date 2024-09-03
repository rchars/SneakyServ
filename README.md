# SneakyServ

SneakyServ is a simple proxy server with built-in authentication, designed to prevent bots and script kiddies from flooding SSH logs with unauthorized access attempts. It hides the actual service behind a proxy, adding an extra layer of security.

## Usage

### Server Side

1. **Configure SSH**:
   - Set your SSH server to listen only on `127.0.0.1:22`.

2. **Run SneakyServ**:
   - Use the following command to start SneakyServ in receive mode:
     ```bash
     python3 sneakyserv.py --recv --passw PASSWORD --lhost PUBLIC_IP --lport PUBLIC_PORT --rhost 127.0.0.1 --rport 22 --client-limit 10 --auth-timeout 3 --buff-size 4096
     ```

### Client Side

1. **Run SneakyServ**:
   - Use the following command to start SneakyServ in send mode:
     ```bash
     python3 sneakyserv.py --send --passw PASSWORD --lhost 127.0.0.1 --lport RANDOM_PORT --rhost PUBLIC_IP --rport PUBLIC_PORT --client-limit 3 --buff-size 4096
     ```

2. **Connect to SSH**:
   - Connect to the SSH server using:
     ```bash
     ssh user@127.0.0.1 -p RANDOM_PORT
     ```

## Command-Line Options

```
usage: sneakyserv.py [-h] --rhost RHOST --lhost LHOST --passw PASSW [--lhost-timeout LHOST_TIMEOUT] [--rhost-timeout RHOST_TIMEOUT] [--client-limit CLIENT_LIMIT] [--auth-timeout AUTH_TIMEOUT] [--rport RPORT] [--lport LPORT] [--buff-size BUFF_SIZE]
                     (--recv | --send)

SneakySSH - Obfuscator for SSH connections.

options:
  -h, --help            show this help message and exit
  --rhost RHOST, -r RHOST
                        The remote IP address to connect to.
  --lhost LHOST, -l LHOST
                        The IP address to listen on.
  --passw PASSW, -p PASSW
                        The banner/password to send/receive (depending on the mode).
  --lhost-timeout LHOST_TIMEOUT
                        The timeout for incoming connections (in seconds).
  --rhost-timeout RHOST_TIMEOUT
                        The timeout for connections to the remote server (in seconds).
  --client-limit CLIENT_LIMIT
                        The maximum number of clients that can be accepted.
  --auth-timeout AUTH_TIMEOUT
                        The authentication timeout (in seconds).
  --rport RPORT, --rp RPORT
                        The port of the remote server.
  --lport LPORT, --lp LPORT
                        The port to listen on.
  --buff-size BUFF_SIZE
                        The buffer size for recv/send.
  --recv                Receive mode: wait for connections, and if the password is correct, forward everything to the server.
  --send                Send mode: send the password first, then forward all data from a specific network program to the server.
```

## License

This project is licensed under the MIT License.
