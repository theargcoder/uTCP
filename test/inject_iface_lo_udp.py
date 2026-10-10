import socket

# Initialize a standard UDP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Construct a comprehensive HTTP/1.1 GET request payload
# Every line must end with \r\n, and the entire header block must end with \r\n\r\n
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
    b"DNT: 1\r\n"  # Do Not Track
    b"Sec-Fetch-Site: none\r\n"
    b"Sec-Fetch-Mode: navigate\r\n"
    b"Sec-Fetch-User: ?1\r\n"
    b"Sec-Fetch-Dest: document\r\n"
    b"\r\n"  # Crucial: Double CRLF at the end to signify the end of the headers
)

# Send the packet over UDP
s.sendto(http_payload, ("127.0.0.1", 443))
