import sys
import os
import enum
import socket
import re
import _thread


class HttpRequestInfo(object):
    """
    Represents a HTTP request information

    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.

    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.

    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.

    requested_host: the requested website, the remote website
    we want to visit.

    requested_port: port of the webserver we want to visit.

    requested_path: path of the requested resource, without
    including the website name.

    NOTE: you need to implement to_http_string() for this class.
    """

    def __init__(self, client_info, method: str, requested_host: str,\
                 requested_port: int,\
                 requested_path: str,\
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        # Headers will be represented as a list of lists
        # for example ["Host", "www.google.com"]
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ["Host", "www.google.com"] note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        As the protocol specifies:

        [request_line]\r\n
        [header]\r\n
        [headers..]\r\n
        \r\n

        (just join the already existing fields by \r\n)

        You still need to convert this string
        to byte array before sending it to the socket,
        keeping it as a string in this stage is to ease
        debugging and testing.
        """
        http_string = self.method+" "+self.requested_path+" HTTP/1.0\r\n"
        for i in range(len(self.headers)):
            for j in range(len(self.headers[i])):
                http_string = http_string + self.headers[i][j]+": "+self.headers[i][j+1]
                http_string += "\r\n"
                break
        http_string += "\r\n"
        return http_string

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        """ Same as above 
                hereeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
                HTTP/1.0 code msg
        """
        error_msg = self.message+" ("+str(self.code)+")"

        return error_msg

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.

    Leave this as is, feel free to add yours.
    """
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


def entry_point(proxy_port_number):
    """
    Entry point, start your code here.

    Please don't delete this function,
    but feel free to modify the code
    inside it.
    """

    setup_sockets(proxy_port_number)
    
    return None


def setup_sockets(proxy_port_number):
    """
    Socket logic MUST NOT be written in the any
    class. Classes know nothing about the sockets.

    But feel free to add your own classes/functions.

    Feel free to delete this function.
    """
    print("Starting HTTP proxy on port:", proxy_port_number)
    
    # when calling socket.listen() pass a number
    # that's larger than 10 to avoid rejecting
    # connections automatically.
    cache = {}
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind(("127.0.0.1",int(proxy_port_number)))
    while True:
        s.listen(4096)
        conn,addr = s.accept()

        print("Address: ",addr)
        _thread.start_new_thread(do_socket_logic,(conn,addr,cache),)
        # request_to_be_send = do_socket_logic(conn,addr)
    

        
    return None


def do_socket_logic(conn,addr,cache):
    

    while True:
        
        print(f"connection from {conn} has been established")
        http_raw_data = []
        while True:
            msg = conn.recv(4096).decode()
            check = msg.split(" ")
            if("http://" in msg.lower() or "www." in msg.lower()):
                conn.send(bytes("Hit enter twice","utf-8"))
            elif(len(check) < 3 and "\r\n" not in check):
                conn.send(bytes("Hit enter twice","utf-8"))
            if(msg == "\r\n"):
                http_raw_data[-1] = http_raw_data[-1]+"\r\n"
                break
            else:
                http_raw_data.append(msg)
        break
    request_to_be_send = http_request_pipeline(conn,http_raw_data)
    if(type(request_to_be_send) == HttpErrorResponse):
            conn.send(request_to_be_send.to_byte_array(request_to_be_send.to_http_string()))
            conn.close()
            
    else:
            if(request_to_be_send.to_http_string() in cache):
                conn.send(cache.get(request_to_be_send.to_http_string()))
                conn.close()
            else:
                s2 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                try:
                    s2.connect((request_to_be_send.requested_host,int(request_to_be_send.requested_port)))
                    s2.send(request_to_be_send.to_byte_array(request_to_be_send.to_http_string()))
                    msg = s2.recv(4096)
                    cache[request_to_be_send.to_http_string()] = msg
                    conn.send((msg))
                    conn.close()
                except:
                    conn.send(bytes("could not resolve "+request_to_be_send.requested_host+" Name or service not known",'UTF-8'))
                    conn.close()
    pass


def http_request_pipeline(source_addr, http_raw_data):
    """
    HTTP request processing pipeline.

    - Validates the given HTTP request and returns
      an error if an invalid request was given.
    - Parses it
    - Returns a sanitized HttpRequestInfo

    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.

    Please don't remove this function, but feel
    free to change its content
    """
    #validate
    

    # Parse HTTP request
        
    check_if_valid = check_http_request_validity((''.join(map(str,http_raw_data))))
    if(check_if_valid == HttpRequestState.GOOD):
        request = parse_http_request(source_addr,(''.join(map(str,http_raw_data))))
        sanitize_http_request(request)
        return request
    elif(check_if_valid == HttpRequestState.INVALID_INPUT):
        error_msg = HttpErrorResponse(400,"Bad request")
        return error_msg
    elif(check_if_valid == HttpRequestState.NOT_SUPPORTED):
        error_msg = HttpErrorResponse(501,"Not implemented")
        return error_msg
    return None


def parse_http_request(source_addr, http_raw_data):
    """
    This function parses a "valid" HTTP request into an HttpRequestInfo
    object.
    """
    fields = str(http_raw_data).split()
    lines = str(http_raw_data).splitlines()


    if(len(lines) == 1):
        lines.append(str(''.join(map(str,http_raw_data))))
    lines = lines[:-1]


    headers = []
    host = ""
    path = ""
    port = 80
    temp = []

    if(fields[1].startswith("/")):
        path = fields[1]

        for s in range(len(fields)): #To get host
            if("Host" in fields[s]):
                host = fields[s+1]
                if(host.startswith("http://")):
                    host = host[7:]
                portCheck = host.split(":")
                if(len(portCheck) > 1):
                    port = portCheck[1]
                    host = fields[s+1][:-1*len(port)-1]
        lines.pop(0)
        if(len(lines) > 0):
            for l in range(len(lines)):
                temp = (lines[l].split(":"))
                if(len(temp) < 3):
                    headers.append(lines[l].split(":"))
                else:
                    headers.append(lines[l].split(":")[:-1])

        for i in range(len(headers)):
            for j in range(len(headers[i])):
                headers[i][j] = headers[i][j].strip() 

        ret = HttpRequestInfo(source_addr,fields[0],host, port, fields[1], headers)

    else:
        host,port,path = get_host_and_port(fields[1])
        
        ret = HttpRequestInfo(source_addr,fields[0] , host, port, path, None)    
    return ret



def get_host_and_port(msg):
    host = ""
    port = 80
    path = ""
    splitted_msg = msg.split(":")
    if(len(splitted_msg) == 3):
        temp = re.findall(r'\d+', splitted_msg[2]) 
        x = list(map(int, temp))
        if(len(x) != 0):
            port = x[0]
        host = splitted_msg[1][2:]
        path = splitted_msg[2][len(str(port)):]


    elif(len(splitted_msg) == 2):
        temp = re.findall(r'\d+', splitted_msg[1])
        x = list(map(int, temp))
        if(len(x) != 0):
            port = x[0]
            host = splitted_msg[0]
            path = splitted_msg[1][len(str(port)):]
        else:
            splitted_msg[1] = splitted_msg[1][2:]
            loc = (splitted_msg[1].find("/"))
            host = splitted_msg[1][:loc]
            path = splitted_msg[1][loc:]

    elif(len(splitted_msg) == 1):
        loc = (splitted_msg[0].find("/"))
        host = splitted_msg[0][:loc]
        path = splitted_msg[0][loc:]
        
    return host,port,path


def check_http_request_validity(http_raw_data) -> HttpRequestState:
    """
    Checks if an HTTP request is valid

    returns:
    One of values in HttpRequestState
    """
    headers = []
    valid_methods = ["GET","PUT","HEAD","POST"]
    fields = str(http_raw_data).split()
    if(fields[1].startswith("http://")):
        fields[1] = fields[1][7:]
    lines = str(http_raw_data).splitlines()
    
    if(len(lines) == 1):
        lines.append(str(''.join(map(str,http_raw_data))))
    lines = lines[:-1]
    
    if(fields[1] == "/" and "Host:" not in fields):
        return HttpRequestState.INVALID_INPUT
    else:
        if(len(lines[0].split()) == 3 and  fields[2] == "HTTP/1.0" and "/" in fields[1] and fields[0] in valid_methods):
            
            if(fields[0] == "GET"):
                for i in range(1,len(lines)):
                    x = lines[i].split(":")
                    headers.append(x)
                    if(len(x) < 2):
                        return HttpRequestState.INVALID_INPUT
                        
                return HttpRequestState.GOOD
            else:
                return HttpRequestState.NOT_SUPPORTED
        else: 
            return HttpRequestState.INVALID_INPUT

def sanitize_http_request(request_info: HttpRequestInfo):
    """
    Puts an HTTP request on the sanitized (standard) form
    by modifying the input request_info object.

    for example, expand a full URL to relative path + Host header.
    r
    returns:
    nothing, but modifies the input object
    """

    if(request_info.headers == None):
        request_info.headers = list()
        request_info.headers.append(["Host",request_info.requested_host])
        


def get_arg(param_index, default=None):

    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*

    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_){,2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    else:
        print(f"[LOG] File name is correct.")


def main():
    """
    Please leave the code in this function as is.

    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    print("\n\n")
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()

    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()

