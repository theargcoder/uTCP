import socket

# Initialize a standard TCP socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Establish the TCP connection
s.connect(("127.0.0.1", 443))

# Construct the HTTP/1.1 GET request payload
http_payload = (
    b"GET /example.html HTTP/1.1\r\n"
    b"Host: 127.0.0.1:443\r\n"
    b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
    b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n"
    b"Accept-Language: en-US,en;q=0.9\r\n"
    b"Accept-Encoding: gzip, deflate, br\r\n"
    b"Connection: keep-alive\r\n"
    b"Upgrade-Insecure-Requests: 1\r\n"
    b"Cache-Control: max-age=0\r\n"
    b"DNT: 1\r\n"
    b"Sec-Fetch-Site: none\r\n"
    b"Sec-Fetch-Mode: navigate\r\n"
    b"Sec-Fetch-User: ?1\r\n"
    b"Sec-Fetch-Dest: document\r\n"
    b"\r\n"
)

# Send the HTTP payload over TCP
s.sendall(http_payload)

s.close()
