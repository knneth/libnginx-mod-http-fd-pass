# nginx http_fd_pass module

libnginx-mod-http-fd-pass is a custom nginx module that forwards incoming client connections to another process using the [SCGI protocol](https://en.wikipedia.org/wiki/Simple_Common_Gateway_Interface).
Uniquely, it sends the actual client file descriptor (FD) via an SCM_RIGHTS ancillary message along with the initial HTTP request headers.

## How It Works

1. Receive Request: Nginx accepts a new client connection (HTTP or HTTPS with [Kernel TLS offload](https://docs.kernel.org/networking/tls-offload.html)).
2. Collect Headers: Once all initial request headers have arrived from the client, the module gathers these headers.
3. SCGI Forward:
   - The module forwards the request headers to a backend process over a UNIX domain socket, adhering to the SCGI protocol.
   - Simultaneously, the client’s file descriptor is passed via an `SCM_RIGHTS` ancillary message.
4. Connection Handoff:
   - For HTTP connections, or for HTTPS connections using kTLS offload (both receive and send), nginx is finished with the connection after handing it off.
     The backend process owns the client connection FD going forward.

This setup effectively lets you implement advanced workflows in your SCGI-based backend (such as specialized I/O handling, zero-copy operations, or custom protocols) while using NGINX as the initial request router.

## Features

- SCGI Integration: Uses the SCGI protocol to transmit request headers to another process.
- FD Handoff via `SCM_RIGHTS`: Passes the client’s socket descriptor to the backend, enabling direct control of the connection.
- Minimal Overhead: Once NGINX hands off the connection, it no longer processes subsequent data for the request (if HTTP or kTLS offload is used in both directions).
- Simple Directives: `fd_pass` can be configured on specific locations, making it easy to enable or disable per context.

## Limitations / Notes

- SCGI-only: This module uses SCGI; it does not support FastCGI, environment variables, or other CGI interfaces.
- Advanced Use Cases: Handing off the FD is powerful but also complex; ensure your SCGI backend can handle raw socket I/O.
- TLS Support: For TLS connections, the module works best with kTLS enabled for both receiving and sending.
  Otherwise, nginx must continue handling SSL/TLS on the connection. Consult the below support matrix.

| OpenSSL version | kTLS offloads for TLSv1.2 | kTLS offloads for TLSv1.3 |
| --- | --- | --- |
| 3.0, 3.1 | Encrypt and decrypt (full handover) | Encrypt only (partial socket handover from Nginx*) |
| 3.2 and later | Encrypt and decrypt (full handover) | Encrypt and decrypt (full handover) |


*) Specifically for OpenSSL versions _below_ 3.2, only sending is possible to offload for TLSv1.3 clients.
For these clients, Nginx retains ownership of receiving and decrypting data from the client in user-space, and forwards the unencrypted data to the backend over UNIX socket.
Still, the backend process will have ownership over sending data to the client since encryption uses Kernel TLS offload.

## Installation

Install a dpkg package from the Releases page or build it from source as outlined below.

Building a module on Debian/Ubuntu:

1. Clone the repository:
   ```
   git clone https://github.com/knneth/libnginx-mod-http-fd-pass
   cd libnginx-mod-http-fd-pass
   ```
2. Build the package:
   ```
   dpkg-buildpackage --build=binary --unsigned-changes --unsigned-buildinfo
   ```
3. Install the package (change the version number as necessary):
   ```
   sudo apt install ../libnginx-mod-http-fd-pass_1.0.0-0_amd64.deb
   ```

Alternatively, it can be compiled into the nginx server (embedded applications):

1. Clone the repository:
   ```
   git clone https://github.com/knneth/libnginx-mod-http-fd-pass
   ```
2. Obtain and extract nginx source code (matching your desired NGINX version)
   ```
   curl -OLR https://nginx.org/download/nginx-x.x.x.tar.gz
   tar xvzf nginx-x.x.x.tar.gz
   cd nginx-x.x.x
   ```
3. Configure nginx with this module:
   ```
   ./configure --add-module=../libnginx-mod-http-fd-pass --with-http_ssl_module [other-options]
   make -j
   ```

## Configuration

To enable the module, add the `fd_pass` directive in the appropriate `location` block. For example:

```
http {
    server {
        listen 80 default_server;
        listen 443 ssl default_server;
        ssl_protocols TLSv1.2 TLSv1.3;
        server_name localhost;

        location /fd_pass_test {
            fd_pass unix:/run/scgi_fdpass.sock;
        }
    }
}
```

## Example SCGI Backend Logic

Your SCGI backend must:
- Receive the netstring-encoded SCGI headers from the UNIX domain socket.
- Extract the client FD from the received ancillary data (SCM_RIGHTS).
- Interact directly with the client socket. For HTTP, TLSv1.2, or when the SCGI header `KTLS_RX=0` is absent, you can continue reading or writing data to this FD as needed.
  - Only encryption is offloaded to kTLS when the SCGI header `KTLS_RX=0` is present.
    You can continue receiving data over the UNIX socket connection, but writing data must use the client FD.
    Upgrade to OpenSSL 3.2 or later to support full connection handover for TLSv1.3 clients.

# Contributing

We welcome contributions that enhance functionality, improve performance, or fix bugs.

# License

This project is licensed under the [MIT License](LICENSE). You are free to use, modify, and distribute this software in accordance with the terms of the license.

# Maintainer

- [knneth](https://github.com/knneth)
