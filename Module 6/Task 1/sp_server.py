#!/usr/bin/env python3
#base server template from: https://gist.github.com/mdonkers/63e115cc0c79b4f6b8b3a6b797e485c7

from http.server import BaseHTTPRequestHandler, HTTPServer
import ctypes
so_file ="/home/isl/.local/lib/stringparser_core.so"
sp_core = ""

class S(BaseHTTPRequestHandler):
    def _set_header_200(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
    def _set_header_404(self):
        self.send_response(404)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        print("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_header_200()
        self.wfile.write("GET request for {}".format(self.path).encode('utf-8'))
        self.wfile.write("ISL - Task 4 String Parser\n\nThis Program does not allow GET-requests. Please re-read the task instructions on how to proceed!\n\n".encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        print("BODY:" + post_data.decode('utf-8'))
        print("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n", str(self.path), str(self.headers), post_data.decode('utf-8'))

        parserResponse = sp_core.stringParser(ctypes.c_char_p(post_data), ctypes.c_uint32(content_length))
        print("Response from Parser: " + parserResponse.decode('utf-8'))
        if("ERROR" in parserResponse.decode('utf-8')):
            self._set_header_404()
        else:
            self._set_header_200()
        self.wfile.write(parserResponse)

def run(server_class=HTTPServer, handler_class=S, port=5111):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print('Starting httpd...\n')
    print('StringParser listening on http://127.0.0.1:' + str(port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print('Stopping httpd...\n')

if __name__ == '__main__':
    from sys import argv

    sp_core = ctypes.CDLL(so_file) #Load Library Files
    sp_core.stringParser.restype = ctypes.c_char_p

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
