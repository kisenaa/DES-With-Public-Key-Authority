import socket
import struct
import ssl
from DES import Des
from RSA import RSA_Algorithm
import time
import json
import threading


class RSA_Container():
    def __init__(self) -> None:
        self.public_key: tuple[int, int] = None
        self.private_key: tuple[int, int] = None

class ClientProgram():
    def __init__(self) -> None:
        self.id             = ""
        self.host                = socket.gethostname()
        self.public_port         = 5022
        self.client_port         = 5023
        self.public_socket       = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket       = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_connection   = None
        self.local_keys : bytes  = '\0'
        self.server_keys: bytes  = '\0'
        self.server_ip           = ""
        self.server_port         = ""
        self.client_address = ""
        self.DES                 = Des()
        self.RSA                 = RSA_Algorithm()
        self.public_auth         = RSA_Container()
        self.local_RSA           = RSA_Container()
        self.client_RSA          = RSA_Container()
        self.des_key: bytes      = '\0'
        self.lock = threading.Lock()

    @staticmethod
    def pack_tuple(int_tuple: tuple[int, int]) -> bytes:
        return struct.pack('qq', *int_tuple) 

    @staticmethod
    def unpack_tuple(packed_data: bytes) -> tuple[int, int]:
        return struct.unpack('qq', packed_data)
    
    @staticmethod
    def pack_rsa(encrypted_message):
        return struct.pack(f'<{len(encrypted_message)}Q', *encrypted_message)

    @staticmethod
    def unpack_rsa(packed_message):
        num_integers = len(packed_message) // 8 
        return list(struct.unpack(f'<{num_integers}Q', packed_message))
    
    def __StartPublicAuthSocket(self):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE 
        self.public_socket = ssl_context.wrap_socket(self.public_socket, server_hostname=self.host)
        
        self.public_socket.connect((self.host, self.public_port)) 
        self.server_ip, self.server_port = self.public_socket.getpeername()
        print(f"Connected to server at IP: {self.server_ip}, Port: {self.server_port}")

        # Additional Validation
        confirmation = input("Do you want to accept this server connection? (yes/no): ")
        if confirmation.lower() == 'no' :
            print("Connection Refused ! Terminating Connection ...")
            self.public_socket.close()
            return False
        else :
            print("Connection Accepted !\n")
            True

    def __MakeClientSocket(self):
        self.client_socket.bind((self.host, self.client_port)) 
        self.client_socket.listen(1)

        # Wrap the socket with SSL
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE 
        ssl_context.load_cert_chain(certfile='server.crt', keyfile='server.key')

        self.client_connection, self.client_address = self.client_socket.accept()
        self.client_connection = ssl_context.wrap_socket(self.client_connection, server_side=True)
        print("Connection from: " + str(self.client_address))

        # Additional Validation
        confirmation = input("Do you want to accept this client connection? (yes/no): ")
        if confirmation.lower() == 'no' :
            print("Connection Refused ! Terminating Connection ...")
            self.client_connection.close()
            return False
        else :
            print("Connection Accepted !")
            True

    def __ConstructMessage(self, message: str, type: str):
        payload = {
            'type': type,
            'message': message
        }
        return json.dumps(payload)

    def __HandleMessage(self):
        # Handle Incoming / Outgoing Message
        while True:
            data = self.client_connection.recv(3024)
            if not data:
                break
            
            # Decrypt the message
            print("\nRaw from client: " + str(data))
            raw_msg = self.DES.Decrypt_using_key(data, self.des_key)
            msg = json.loads(raw_msg)
            print("decrypted from client: ", msg)
            print()

            if msg['type'] == 'GENERATE':
                # Receive Des Key DES Key
                print("\nGetting DES Key from Client A ....")
                message = self.client_connection.recv(3024)
                unpacked_key = self.unpack_rsa(message)

                # Decrypt with  Our Private Key
                encrypted_des = bytes.fromhex(self.RSA.decrypt(unpacked_key, self.local_RSA.private_key))
                # Decrypt with Client A Public Key
                self.des_key = bytes.fromhex(self.RSA.decrypt(self.unpack_rsa(encrypted_des), self.client_RSA.public_key))
                
                print(f"DES Key: ", self.des_key, '\n')

                continue

            data = input(' -> ')
            # Encrypt the string before sending to client
            data = self.__ConstructMessage(data, 'MSG').encode('utf-8') 
            encrypted_message = self.DES.Encrypt(data, self.des_key)
            self.client_connection.send(encrypted_message) 

        self.client_connection.close()
        self.public_socket.close()

    def Start(self):
        if self.__StartPublicAuthSocket() == False:
            return
        
        # Receive Server RSA keys from server
        print("Waiting for Public Authority to send it's RSA Public Key...")
        server_data = self.public_socket.recv(3024)
        self.public_auth.public_key = self.unpack_tuple(server_data)
        print(f"Public Authority - Public Key : ", self.public_auth.public_key, '\n')

        # Send our RSA Keys to Public Authority Server
        print("Register our Public key to Public Authority Server....")
        self.local_RSA.public_key, self.local_RSA.private_key = self.RSA.generate_keypair()
        self.public_socket.send(self.pack_tuple(self.local_RSA.public_key))        

        print(f"Local RSA - Public Key : ", self.local_RSA.public_key)
        print(f"Local RSA - Private Key: ", self.local_RSA.private_key, '\n')

        # Set our ID identity
        self.id = self.public_socket.recv(3024).decode()
        print(f"Our Identity: ", self.id)

        if self.__MakeClientSocket() == False:
            return
        
        # Wait for client A talk to us
        a_message = self.client_connection.recv(3024)
        print("\nEncrypted message from client - A : ")
        print(a_message)

        # Decrypt Client A message
        print("\nDecrypting client A message ...")
        message = self.unpack_rsa(a_message)
        message_json = json.loads(self.RSA.decrypt(message, self.local_RSA.private_key))
        print(message_json)
        print()

        N1 = message_json['N1']

        # Request Client A public key to Public Authority
        print("Requesting client A public key .....")
        payload = {
        "type": "REQUEST_PUBLIC_KEY",
        "id": message_json['id'],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")  
        }

        self.public_socket.sendall(json.dumps(payload).encode('utf-8'))

        response = self.public_socket.recv(3024)
        response = self.unpack_rsa(response)
        response_json = json.loads(self.RSA.decrypt(response, self.public_auth.public_key))
        self.client_RSA.public_key = self.unpack_tuple(bytes.fromhex(response_json['public_key']))
        print(f"Public Authority Response: ", response_json)
        print(f"Client A - Public Key: ", self.client_RSA.public_key, '\n')

        # Send Our Response To Client A
        N2 = self.DES.Random_Bytes(8).hex()
        payload = {
            "type": "STEP_6",
            "id": "B",
            "N1": message_json['N1'],
            "N2": N2,
        }

        print("Sending our response to Client A ....")
        print(payload)
        message = self.RSA.encrypt(json.dumps(payload), self.client_RSA.public_key)
        self.client_connection.send(self.pack_rsa(message))

        # Get a message from client A
        response = self.client_connection.recv(3024)
        response = self.unpack_rsa(response)
        response_json = json.loads(self.RSA.decrypt(response, self.local_RSA.private_key))
        print("\nDecrypting client A message ...")
        print(response_json)

        if(response_json['N2'] != N2):
            print("Invalid Nonce N2")
            return

        # Receive Des Key DES Key
        print("\nGetting DES Key from Client A ....")
        message = self.client_connection.recv(3024)
        unpacked_key = self.unpack_rsa(message)

        # Decrypt with  Our Private Key
        encrypted_des = bytes.fromhex(self.RSA.decrypt(unpacked_key, self.local_RSA.private_key))
        # Decrypt with Client A Public Key
        self.des_key = bytes.fromhex(self.RSA.decrypt(self.unpack_rsa(encrypted_des), self.client_RSA.public_key))
        
        print(f"DES Key: ", self.des_key, '\n')
        
        # Handle Encrypted Communication
        self.__HandleMessage()


if __name__ == '__main__':
    Program = ClientProgram()
    Program.Start()


# Keys are distributed and exchange using secure RSA Keys

# 1. Client send keys -> Server receive keys
# 2. Server send keys -> Client receive key

# 1. Client encrypt -> Server Decrypt
# 2. Server Encrypt -> Client Decrypt